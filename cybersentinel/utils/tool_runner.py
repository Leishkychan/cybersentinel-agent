"""Shared utility for running external tools as subprocesses.

Provides:
- Synchronous tool execution with timeout handling
- Parallel tool execution using thread pools
- Tool availability checking
- Version detection
- Automatic audit logging
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolCommand:
    """A command to execute using ToolRunner."""
    tool_name: str
    args: list[str]
    timeout: int = 300
    parse_json: bool = False
    working_dir: Optional[str] = None


@dataclass
class ToolResult:
    """Result of executing a tool command."""
    tool_name: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    parsed_json: Optional[dict] = None
    success: bool = field(init=False)

    def __post_init__(self):
        """Automatically set success based on exit code."""
        self.success = self.exit_code == 0

    def to_dict(self) -> dict:
        """Serialize for logging."""
        return {
            "tool_name": self.tool_name,
            "exit_code": self.exit_code,
            "success": self.success,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "duration_ms": self.duration_ms,
            "parsed_json": self.parsed_json is not None,
        }


class ToolRunner:
    """Execute external tools as subprocesses.

    Features:
    - Automatic timeout handling with SIGTERM/SIGKILL
    - JSON output parsing
    - Tool availability checking
    - Version detection
    - Parallel execution with thread pools
    - Automatic logging to audit trail
    """

    def __init__(self, audit_log_callback=None):
        """Initialize the tool runner.

        Args:
            audit_log_callback: Optional callback for audit logging
                               (called with (event_type, details) on each run)
        """
        self.logger = logging.getLogger(__name__)
        self.audit_log_callback = audit_log_callback

    def run(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = 300,
        parse_json: bool = False,
        working_dir: Optional[str] = None,
    ) -> ToolResult:
        """Execute a tool and return structured result.

        Args:
            tool_name: Name of the tool to run (must be in PATH or absolute path)
            args: List of arguments to pass
            timeout: Timeout in seconds (default 300)
            parse_json: If True, attempt to parse stdout as JSON
            working_dir: Working directory for execution

        Returns:
            ToolResult with exit code, stdout, stderr, duration, and optional parsed JSON

        Raises:
            FileNotFoundError: If tool is not found
            subprocess.TimeoutExpired: If timeout exceeded (caught and converted to result)
        """
        start_time = time.time()

        # Verify tool exists
        if not self.check_tool_available(tool_name):
            self.logger.error(f"Tool not found: {tool_name}")
            raise FileNotFoundError(f"Tool not found in PATH: {tool_name}")

        # Build command
        cmd = [tool_name] + args
        self.logger.info(f"Executing: {' '.join(cmd)}")

        # Log to audit trail if callback provided
        if self.audit_log_callback:
            self.audit_log_callback("tool_execution_started", {
                "tool": tool_name,
                "args": args,
            })

        try:
            # Execute with timeout
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            # Parse JSON if requested
            parsed_json = None
            if parse_json and process.stdout:
                try:
                    parsed_json = json.loads(process.stdout)
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse JSON from {tool_name}")

            result = ToolResult(
                tool_name=tool_name,
                exit_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration_ms=duration_ms,
                parsed_json=parsed_json,
            )

            # Log result
            if self.audit_log_callback:
                self.audit_log_callback("tool_execution_completed", result.to_dict())

            if result.success:
                self.logger.info(f"Tool {tool_name} succeeded in {duration_ms}ms")
            else:
                self.logger.warning(
                    f"Tool {tool_name} failed with exit code {result.exit_code}"
                )

            return result

        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)

            result = ToolResult(
                tool_name=tool_name,
                exit_code=-1,
                stdout="",
                stderr=f"Timeout after {timeout} seconds",
                duration_ms=duration_ms,
            )

            if self.audit_log_callback:
                self.audit_log_callback("tool_timeout", {
                    "tool": tool_name,
                    "timeout_seconds": timeout,
                    "duration_ms": duration_ms,
                })

            self.logger.error(f"Tool {tool_name} timed out after {timeout}s")
            return result

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)

            result = ToolResult(
                tool_name=tool_name,
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                duration_ms=duration_ms,
            )

            if self.audit_log_callback:
                self.audit_log_callback("tool_execution_error", {
                    "tool": tool_name,
                    "error": str(e),
                })

            self.logger.error(f"Error executing {tool_name}: {e}")
            return result

    def run_parallel(
        self,
        commands: list[ToolCommand],
        max_workers: int = 5,
    ) -> list[ToolResult]:
        """Execute multiple tools in parallel.

        Args:
            commands: List of ToolCommand objects
            max_workers: Maximum number of parallel workers (default 5)

        Returns:
            List of ToolResult objects (order not guaranteed)
        """
        results = []

        self.logger.info(f"Executing {len(commands)} tools in parallel (max {max_workers} workers)")

        if self.audit_log_callback:
            self.audit_log_callback("parallel_execution_started", {
                "num_commands": len(commands),
                "max_workers": max_workers,
            })

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all commands
            futures = {
                executor.submit(
                    self.run,
                    cmd.tool_name,
                    cmd.args,
                    timeout=cmd.timeout,
                    parse_json=cmd.parse_json,
                    working_dir=cmd.working_dir,
                ): cmd.tool_name
                for cmd in commands
            }

            # Collect results as they complete
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Parallel execution completed: {tool_name}")
                except Exception as e:
                    self.logger.error(f"Error in parallel execution of {tool_name}: {e}")
                    results.append(ToolResult(
                        tool_name=tool_name,
                        exit_code=-1,
                        stdout="",
                        stderr=f"Parallel execution error: {str(e)}",
                        duration_ms=0,
                    ))

        if self.audit_log_callback:
            self.audit_log_callback("parallel_execution_completed", {
                "num_commands": len(commands),
                "num_results": len(results),
                "success_count": sum(1 for r in results if r.success),
            })

        return results

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is installed and available in PATH.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is available, False otherwise
        """
        # If it's an absolute path, check if file exists
        if "/" in tool_name or "\\" in tool_name:
            import os
            return os.path.exists(tool_name) and os.access(tool_name, os.X_OK)

        # Otherwise, check if it's in PATH
        return shutil.which(tool_name) is not None

    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get version string of an installed tool.

        Attempts common version detection patterns:
        - tool --version
        - tool -v
        - tool version

        Args:
            tool_name: Name of the tool

        Returns:
            Version string if detected, None otherwise
        """
        if not self.check_tool_available(tool_name):
            return None

        # Try common version flags
        version_flags = ["--version", "-v", "-version", "version"]

        for flag in version_flags:
            try:
                result = subprocess.run(
                    [tool_name, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0 and result.stdout:
                    version_string = result.stdout.strip().split("\n")[0]
                    self.logger.info(f"Detected {tool_name}: {version_string}")
                    return version_string

            except Exception:
                continue

        self.logger.debug(f"Could not detect version for {tool_name}")
        return None
