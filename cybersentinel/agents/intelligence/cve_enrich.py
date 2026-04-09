"""CVE Enrichment Agent — enriches findings with NVD, EPSS, CISA KEV data."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


class CVEEnrichmentAgent(BaseAgent):
    """Enriches CVE findings with NVD, EPSS, and CISA KEV data."""

    name = "cve_enrichment"
    description = "Enriches CVE findings with NVD, EPSS, and CISA KEV data"

    def __init__(self, session: Session):
        super().__init__(session)
        self.cache_dir = Path.home() / ".cybersentinel" / "cache" / "cve"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cisa_kev_cache = None
        self.last_request_time = 0
        self.request_interval = 0.6  # 5 req/30sec = ~0.6sec per request

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Enrich CVE findings from context with NVD/EPSS/CISA KEV data.

        Args:
            target: Target identifier
            context: Dict with 'findings' key containing Finding objects

        Returns:
            Enriched findings
        """
        if not self.validate(target, "CVE enrichment analysis"):
            return []

        findings = context.get("findings", [])
        if not findings:
            self.log("No findings to enrich")
            return []

        enriched = []
        for finding in findings:
            if not finding.cve_ids:
                enriched.append(finding)
                continue

            try:
                enriched_finding = self._enrich_cve_finding(finding)
                enriched.append(enriched_finding)
            except Exception as e:
                self.log(f"Error enriching CVE {finding.cve_ids}: {e}")
                enriched.append(finding)

        return enriched

    def _enrich_cve_finding(self, finding: Finding) -> Finding:
        """Enrich a single CVE finding."""
        for cve_id in finding.cve_ids:
            cve_data = self._get_nvd_data(cve_id)
            if not cve_data:
                continue

            # Extract NVD data
            if "baseScore" in cve_data:
                finding.cvss_score = cve_data.get("baseScore")
                finding.cvss_vector = cve_data.get("vector")

            # Get EPSS score
            epss_data = self._get_epss_data(cve_id)
            if epss_data:
                finding.epss_score = epss_data.get("epss")

            # Check CISA KEV
            if self._is_cisa_kev(cve_id):
                finding.cisa_kev = True

            finding.evidence += self._format_enrichment_evidence(cve_data, epss_data)

        return finding

    def _get_nvd_data(self, cve_id: str) -> Optional[dict]:
        """Query NVD for CVE data with caching."""
        cache_file = self.cache_dir / f"{cve_id}.json"

        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    return json.load(f)
            except Exception as e:
                self.log(f"Cache read error for {cve_id}: {e}")

        # In production, this would make an actual HTTP request to NVD
        # For now, return None (findings will be enriched in live environment)
        self.log(f"NVD lookup for {cve_id} would query: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")

        return None

    def _get_epss_data(self, cve_id: str) -> Optional[dict]:
        """Query EPSS API for exploitation probability."""
        cache_file = self.cache_dir / f"{cve_id}_epss.json"

        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    return json.load(f)
            except Exception as e:
                self.log(f"EPSS cache read error for {cve_id}: {e}")

        # Rate limiting
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_interval:
            time.sleep(self.request_interval - elapsed)

        self.log(f"EPSS lookup for {cve_id} would query: https://api.first.org/data/v1/epss?cve={cve_id}")
        self.last_request_time = time.time()

        return None

    def _load_cisa_kev(self) -> dict:
        """Load CISA KEV list."""
        if self.cisa_kev_cache is not None:
            return self.cisa_kev_cache

        cache_file = self.cache_dir / "cisa_kev.json"

        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    self.cisa_kev_cache = json.load(f)
                    return self.cisa_kev_cache
            except Exception as e:
                self.log(f"CISA KEV cache read error: {e}")

        # In production, fetch from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        self.log("CISA KEV would be loaded from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

        self.cisa_kev_cache = {"vulnerabilities": []}
        return self.cisa_kev_cache

    def _is_cisa_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV list."""
        kev_data = self._load_cisa_kev()
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return True
        return False

    def _format_enrichment_evidence(self, nvd_data: Optional[dict], epss_data: Optional[dict]) -> str:
        """Format enrichment data as evidence."""
        evidence = "\n\n=== CVE Enrichment Data ===\n"

        if nvd_data:
            evidence += f"CVSS Score: {nvd_data.get('baseScore', 'N/A')}\n"
            evidence += f"CVSS Vector: {nvd_data.get('vector', 'N/A')}\n"

        if epss_data:
            evidence += f"EPSS Score: {epss_data.get('epss', 'N/A')}\n"

        return evidence
