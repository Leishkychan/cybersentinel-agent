"""Port Scanning Agent — Layer 1 Reconnaissance.

Wraps masscan and nmap to discover open ports and services.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


class PortScanAgent(BaseAgent):
    """Discovers open ports and services using masscan and nmap."""

    name = "portscan"
    description = "Port scanning — discovers open ports and services"

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Discover open ports and services on target.

        Args:
            target: The target IP or hostname
            context: Additional context, typically contains {'target': '192.168.1.1'}

        Returns:
            List of Finding objects, one per open port with service info
        """
        self.validate(target, f"Port scanning of {target}")
        self.log(f"Starting port scan on {target}")

        findings: list[Finding] = []
        open_ports = {}

        # First, do fast port discovery with masscan
        discovered_ports = self._run_masscan(target)
        if discovered_ports:
            self.log(f"masscan discovered {len(discovered_ports)} open ports")
            open_ports.update(discovered_ports)

        # Then, run detailed service detection with nmap on found ports
        if open_ports:
            port_list = ",".join(str(p) for p in sorted(open_ports.keys()))
            nmap_results = self._run_nmap(target, port_list)
            if nmap_results:
                self.log(f"nmap detailed scan on {len(nmap_results)} ports")
                open_ports.update(nmap_results)

        # Convert to findings
        severity_map = {
            22: Severity.LOW,    # SSH
            23: Severity.HIGH,   # Telnet (unencrypted)
            80: Severity.LOW,    # HTTP
            443: Severity.LOW,   # HTTPS
            3306: Severity.MEDIUM,  # MySQL
            5432: Severity.MEDIUM,  # PostgreSQL
            6379: Severity.HIGH,  # Redis
            27017: Severity.CRITICAL,  # MongoDB
            9200: Severity.CRITICAL,  # Elasticsearch
        }

        for port in sorted(open_ports.keys()):
            service_info = open_ports[port]
            service_name = service_info.get("name", "unknown")
            service_version = service_info.get("version", "")
            product = service_info.get("product", "")

            # Determine severity
            severity = severity_map.get(port, Severity.MEDIUM)

            # Build description
            desc_parts = [f"Port {port}/tcp is open"]
            if service_name:
                desc_parts.append(f"Service: {service_name}")
            if service_version:
                desc_parts.append(f"Version: {service_version}")
            if product:
                desc_parts.append(f"Product: {product}")

            description = " — ".join(desc_parts)

            findings.append(Finding(
                title=f"Open Port: {port}/{service_name}",
                severity=severity,
                description=description,
                affected_component=f"{target}:{port}",
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1046"],  # Network Service Discovery
                evidence=f"Open port discovered on {target}",
                confidence="high",
            ))

        self.log(f"Port scan complete: {len(findings)} open ports found")
        return findings

    def _run_masscan(self, target: str) -> dict:
        """Run masscan for fast port discovery.

        Returns:
            Dict mapping port number to service info
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name

            cmd = ["masscan", target, "-p1-65535", "--rate=1000", "-oJ", output_file]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                self.log(f"masscan failed: {result.stderr}")
                return {}

            ports = {}
            try:
                with open(output_file, 'r') as f:
                    content = f.read().strip()
                    if content.startswith('{'):
                        # masscan can output as JSON object with "ports" array
                        data = json.loads(content)
                        port_list = data.get("ports", [])
                        for port_entry in port_list:
                            port_num = port_entry.get("ports", [{}])[0].get("port")
                            if port_num:
                                ports[port_num] = {"name": "unknown"}
                    else:
                        # Or as JSONL
                        for line in content.split('\n'):
                            if not line.strip() or line.startswith('{') == False:
                                continue
                            try:
                                entry = json.loads(line)
                                if "ports" in entry:
                                    for port_info in entry["ports"]:
                                        port_num = port_info.get("port")
                                        if port_num:
                                            ports[port_num] = {"name": "unknown"}
                            except json.JSONDecodeError:
                                pass
            except FileNotFoundError:
                self.log(f"masscan output file not found: {output_file}")

            return ports

        except FileNotFoundError:
            self.log("masscan not found on system")
            return {}
        except subprocess.TimeoutExpired:
            self.log("masscan timed out")
            return {}
        except Exception as e:
            self.log(f"masscan error: {str(e)}")
            return {}

    def _run_nmap(self, target: str, ports: str) -> dict:
        """Run nmap for service detection.

        Args:
            target: Target IP or hostname
            ports: Comma-separated port list (e.g., "80,443,22")

        Returns:
            Dict mapping port number to service info with version
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                output_file = f.name

            cmd = ["nmap", "-sV", "-sC", "-p", ports, target, "-oX", output_file]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                self.log(f"nmap scan had issues: {result.stderr}")

            ports_info = {}
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()

                for host in root.findall(".//host"):
                    for port_elem in host.findall(".//port"):
                        port_num = int(port_elem.get("portid"))
                        state = port_elem.find("state")

                        if state is not None and state.get("state") == "open":
                            service = port_elem.find("service")
                            service_info = {"name": "unknown"}

                            if service is not None:
                                if service.get("name"):
                                    service_info["name"] = service.get("name")
                                if service.get("product"):
                                    service_info["product"] = service.get("product")
                                if service.get("version"):
                                    service_info["version"] = service.get("version")
                                if service.get("extrainfo"):
                                    service_info["extrainfo"] = service.get("extrainfo")

                            ports_info[port_num] = service_info

            except (FileNotFoundError, ET.ParseError) as e:
                self.log(f"Error parsing nmap output: {str(e)}")

            return ports_info

        except FileNotFoundError:
            self.log("nmap not found on system")
            return {}
        except subprocess.TimeoutExpired:
            self.log("nmap timed out")
            return {}
        except Exception as e:
            self.log(f"nmap error: {str(e)}")
            return {}
