"""Configuration management for CyberSentinel.

Handles:
- Loading configuration from YAML or environment variables
- Encrypted API key storage at rest (using Fernet)
- Fallback mechanisms for missing configuration
- Hardcoded safety constraints (e.g., always-blocked Nuclei tags)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


@dataclass
class ScanDefaults:
    """Default scan configuration."""
    timeout_seconds: int = 300
    max_parallel_agents: int = 5
    retry_failed_agents: bool = True
    max_retries: int = 2


@dataclass
class ReportingConfig:
    """Reporting configuration."""
    include_evidence: bool = True
    redact_sensitive_data: bool = True
    format: str = "json"  # "json", "html", "pdf"
    send_email: bool = False
    email_recipients: list[str] = field(default_factory=list)


class SentinelConfig:
    """Central configuration manager for CyberSentinel.

    Loads configuration from:
    1. config/sentinel.yaml (if exists)
    2. Environment variables (fallback)
    3. Built-in defaults

    API keys are encrypted at rest using Fernet (AES-128).
    """

    # Hardcoded Nuclei tags that can NEVER be removed
    ALWAYS_BLOCKED_NUCLEI_TAGS = {
        "exploit",
        "dos",
        "brute-force",
        "fuzzing",
    }

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.

        Args:
            config_path: Path to sentinel.yaml config file (optional)
        """
        self.logger = logging.getLogger(__name__)
        self._api_keys: dict[str, str] = {}  # Encrypted in-memory storage
        self._config: dict = {}
        self._encryption_key: Optional[bytes] = None

        # Initialize encryption
        self._init_encryption()

        # Load configuration
        if config_path:
            self._load_yaml(config_path)
        else:
            # Try default locations
            default_paths = [
                "config/sentinel.yaml",
                "/etc/cybersentinel/config.yaml",
                os.path.expanduser("~/.cybersentinel/config.yaml"),
            ]
            for path in default_paths:
                if os.path.exists(path):
                    self._load_yaml(path)
                    break
            else:
                self.logger.warning("No config file found, using environment variables and defaults")

        # Load from environment variables (overrides YAML)
        self._load_from_env()

    def _init_encryption(self) -> None:
        """Initialize Fernet encryption for API keys.

        Uses CYBERSENTINEL_ENCRYPTION_KEY env var if available,
        otherwise generates a temporary key (not persisted).
        """
        key_env = os.getenv("CYBERSENTINEL_ENCRYPTION_KEY")

        if key_env:
            try:
                self._encryption_key = key_env.encode()
                Fernet(self._encryption_key)  # Validate format
                self.logger.info("Using encryption key from environment")
            except Exception as e:
                self.logger.warning(f"Invalid encryption key in env: {e}, generating temporary key")
                self._encryption_key = Fernet.generate_key()
        else:
            # Generate temporary key (lost on restart)
            self._encryption_key = Fernet.generate_key()
            self.logger.info("Generated temporary encryption key (not persisted)")

    def _load_yaml(self, config_path: str) -> None:
        """Load configuration from YAML file.

        Args:
            config_path: Path to sentinel.yaml
        """
        path = Path(config_path)

        if not path.exists():
            self.logger.warning(f"Config file not found: {config_path}")
            return

        try:
            with open(path, "r") as f:
                self._config = yaml.safe_load(f) or {}
            self.logger.info(f"Loaded config from {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")

    def _load_from_env(self) -> None:
        """Load configuration from environment variables.

        Overrides YAML configuration.
        """
        # API keys from environment
        if api_key := os.getenv("SHODAN_API_KEY"):
            self.set_api_key("shodan", api_key)

        if api_key := os.getenv("VIRUSTOTAL_API_KEY"):
            self.set_api_key("virustotal", api_key)

        if api_key := os.getenv("CENSYS_API_ID"):
            self.set_api_key("censys_id", api_key)

        if api_key := os.getenv("CENSYS_API_SECRET"):
            self.set_api_key("censys_secret", api_key)

        # Model configuration from environment
        if enabled_models := os.getenv("ENABLED_MODELS"):
            self._config.setdefault("models", {})["enabled"] = enabled_models.split(",")

    def set_api_key(self, provider: str, key: str) -> None:
        """Encrypt and store an API key.

        Args:
            provider: Name of the provider (e.g., "shodan", "virustotal")
            key: The API key to store

        Raises:
            ValueError: If key is empty
        """
        if not key:
            raise ValueError(f"API key for {provider} cannot be empty")

        if not self._encryption_key:
            raise RuntimeError("Encryption not initialized")

        try:
            cipher = Fernet(self._encryption_key)
            encrypted = cipher.encrypt(key.encode()).decode()
            self._api_keys[provider] = encrypted
            self.logger.info(f"Stored encrypted API key for {provider}")
        except Exception as e:
            self.logger.error(f"Failed to encrypt API key for {provider}: {e}")
            raise

    def get_api_key(self, provider: str) -> Optional[str]:
        """Decrypt and retrieve an API key.

        Args:
            provider: Name of the provider

        Returns:
            Decrypted API key, or None if not found
        """
        if provider not in self._api_keys:
            self.logger.debug(f"No API key found for {provider}")
            return None

        try:
            cipher = Fernet(self._encryption_key)
            encrypted = self._api_keys[provider].encode()
            decrypted = cipher.decrypt(encrypted).decode()
            return decrypted
        except Exception as e:
            self.logger.error(f"Failed to decrypt API key for {provider}: {e}")
            return None

    def get_enabled_models(self) -> list[str]:
        """Get list of enabled AI models.

        Returns:
            List of model names (e.g., ["claude-3-opus", "gpt-4"])
        """
        models = self._config.get("models", {}).get("enabled", [])

        # Default if not configured
        if not models:
            models = ["claude-3-opus"]
            self.logger.info(f"Using default models: {models}")

        return models

    def get_scan_defaults(self) -> ScanDefaults:
        """Get scan configuration defaults.

        Returns:
            ScanDefaults object with timeout, parallelism, etc.
        """
        scan_config = self._config.get("scanning", {})

        return ScanDefaults(
            timeout_seconds=scan_config.get("timeout_seconds", 300),
            max_parallel_agents=scan_config.get("max_parallel_agents", 5),
            retry_failed_agents=scan_config.get("retry_failed_agents", True),
            max_retries=scan_config.get("max_retries", 2),
        )

    def get_nuclei_blocked_tags(self) -> set[str]:
        """Get Nuclei tags that are blocked from running.

        The always-blocked tags (exploit, dos, brute-force, fuzzing) are
        hardcoded and cannot be removed, even if user config requests it.

        Returns:
            Set of blocked tag names
        """
        user_blocked = set(self._config.get("nuclei", {}).get("blocked_tags", []))

        # Always include hardcoded blocked tags
        all_blocked = user_blocked | self.ALWAYS_BLOCKED_NUCLEI_TAGS

        self.logger.info(f"Nuclei blocked tags: {all_blocked}")
        return all_blocked

    def get_reporting_config(self) -> ReportingConfig:
        """Get reporting configuration.

        Returns:
            ReportingConfig object
        """
        report_config = self._config.get("reporting", {})

        return ReportingConfig(
            include_evidence=report_config.get("include_evidence", True),
            redact_sensitive_data=report_config.get("redact_sensitive_data", True),
            format=report_config.get("format", "json"),
            send_email=report_config.get("send_email", False),
            email_recipients=report_config.get("email_recipients", []),
        )

    def get_raw_config(self) -> dict:
        """Get the entire configuration dictionary.

        Returns:
            Raw config dict (for advanced usage)
        """
        return dict(self._config)

    def to_dict(self) -> dict:
        """Export safe configuration (excludes encrypted keys).

        Returns:
            Configuration dict with redacted secrets
        """
        return {
            "models_enabled": self.get_enabled_models(),
            "scan_defaults": {
                "timeout_seconds": self.get_scan_defaults().timeout_seconds,
                "max_parallel_agents": self.get_scan_defaults().max_parallel_agents,
                "retry_failed_agents": self.get_scan_defaults().retry_failed_agents,
            },
            "nuclei_blocked_tags": list(self.get_nuclei_blocked_tags()),
            "reporting": {
                "include_evidence": self.get_reporting_config().include_evidence,
                "redact_sensitive_data": self.get_reporting_config().redact_sensitive_data,
                "format": self.get_reporting_config().format,
            },
            "api_keys_configured": list(self._api_keys.keys()),
        }

    @staticmethod
    def create_default_yaml(output_path: str = "config/sentinel.yaml") -> None:
        """Create a default configuration file.

        Args:
            output_path: Where to write the default config
        """
        default_config = {
            "models": {
                "enabled": ["claude-3-opus"],
            },
            "scanning": {
                "timeout_seconds": 300,
                "max_parallel_agents": 5,
                "retry_failed_agents": True,
                "max_retries": 2,
            },
            "nuclei": {
                "blocked_tags": [
                    # User can add more here, but exploit, dos, brute-force, fuzzing are always blocked
                    "critical_rce",
                ],
            },
            "reporting": {
                "include_evidence": True,
                "redact_sensitive_data": True,
                "format": "json",
                "send_email": False,
                "email_recipients": [],
            },
            "api_keys": {
                "_comment": "Use environment variables instead: SHODAN_API_KEY, VIRUSTOTAL_API_KEY, etc.",
            },
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Created default config at {output_path}")
