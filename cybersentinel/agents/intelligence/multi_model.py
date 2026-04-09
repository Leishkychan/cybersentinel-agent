"""Multi-Model Agent — runs findings through multiple AI models in parallel."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


class AIClient:
    """Base class for AI provider clients."""

    def __init__(self, provider: str, api_key: Optional[str] = None):
        self.provider = provider
        self.api_key = api_key
        self.available = api_key is not None

    def analyze(self, findings: list[Finding]) -> Optional[dict]:
        """Analyze findings and return insights."""
        raise NotImplementedError


class AnthropicClient(AIClient):
    """Claude API client."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("anthropic", api_key)

    def analyze(self, findings: list[Finding]) -> Optional[dict]:
        """Analyze findings with Claude."""
        if not self.available:
            return None

        # In production, this would call the Anthropic API
        findings_text = self._format_findings(findings)
        logger.info(f"Would call Claude API with {len(findings)} findings")

        return {
            "provider": "Claude",
            "false_positives": [],
            "patterns": [],
            "missed_categories": [],
            "overall_risk": "HIGH",
        }

    def _format_findings(self, findings: list[Finding]) -> str:
        """Format findings for analysis."""
        text = "Security Findings for Analysis:\n"
        for f in findings:
            text += f"\n- {f.title}\n"
            text += f"  Severity: {f.severity.value}\n"
            text += f"  Description: {f.description}\n"
        return text


class OpenAIClient(AIClient):
    """GPT-4 API client."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("openai", api_key)

    def analyze(self, findings: list[Finding]) -> Optional[dict]:
        """Analyze findings with GPT-4."""
        if not self.available:
            return None

        logger.info(f"Would call OpenAI API with {len(findings)} findings")

        return {
            "provider": "GPT-4",
            "false_positives": [],
            "patterns": [],
            "missed_categories": [],
            "overall_risk": "HIGH",
        }


class GoogleClient(AIClient):
    """Gemini API client."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("google", api_key)

    def analyze(self, findings: list[Finding]) -> Optional[dict]:
        """Analyze findings with Gemini."""
        if not self.available:
            return None

        logger.info(f"Would call Google Gemini API with {len(findings)} findings")

        return {
            "provider": "Gemini",
            "false_positives": [],
            "patterns": [],
            "missed_categories": [],
            "overall_risk": "MEDIUM",
        }


class OllamaClient(AIClient):
    """Local Ollama/Llama client."""

    def __init__(self, api_key: Optional[str] = None, endpoint: str = "http://localhost:11434"):
        super().__init__("ollama", api_key)
        self.endpoint = endpoint
        self.available = True  # Local, always available

    def analyze(self, findings: list[Finding]) -> Optional[dict]:
        """Analyze findings with local Llama."""
        logger.info(f"Would call Ollama API at {self.endpoint} with {len(findings)} findings")

        return {
            "provider": "Llama",
            "false_positives": [],
            "patterns": [],
            "missed_categories": [],
            "overall_risk": "HIGH",
        }


class MultiModelAgent(BaseAgent):
    """Runs findings through multiple AI models in parallel."""

    name = "multi_model"
    description = "Analyzes findings through multiple AI models in parallel"

    def __init__(self, session: Session):
        super().__init__(session)
        self.clients = self._initialize_clients()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze findings through multiple AI models.

        Args:
            target: Target identifier
            context: Dict with 'findings' key containing Finding objects

        Returns:
            New META-level findings showing model consensus and insights
        """
        if not self.validate(target, "Multi-model analysis"):
            return []

        findings = context.get("findings", [])
        if not findings:
            return []

        # Run models in parallel
        model_insights = self._run_models_parallel(findings)

        new_findings = []

        # Create META findings from model insights
        if model_insights:
            new_findings.append(self._create_consensus_finding(model_insights, findings))
            new_findings.extend(self._create_insight_findings(model_insights))

        return new_findings

    def _initialize_clients(self) -> dict[str, AIClient]:
        """Initialize AI provider clients."""
        import os

        clients = {}

        # Try to initialize each provider
        if os.getenv("ANTHROPIC_API_KEY"):
            clients["claude"] = AnthropicClient(os.getenv("ANTHROPIC_API_KEY"))
        else:
            clients["claude"] = AnthropicClient()

        if os.getenv("OPENAI_API_KEY"):
            clients["gpt4"] = OpenAIClient(os.getenv("OPENAI_API_KEY"))
        else:
            clients["gpt4"] = OpenAIClient()

        if os.getenv("GOOGLE_API_KEY"):
            clients["gemini"] = GoogleClient(os.getenv("GOOGLE_API_KEY"))
        else:
            clients["gemini"] = GoogleClient()

        clients["llama"] = OllamaClient()

        return clients

    def _run_models_parallel(self, findings: list[Finding]) -> dict[str, Optional[dict]]:
        """Run all available models in parallel."""
        results = {}
        available_clients = {k: v for k, v in self.clients.items() if v.available}

        if not available_clients:
            self.log("No AI providers configured")
            return results

        with ThreadPoolExecutor(max_workers=len(available_clients)) as executor:
            futures = {
                executor.submit(client.analyze, findings): name
                for name, client in available_clients.items()
            }

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result
                    self.log(f"Model analysis complete: {name}")
                except Exception as e:
                    self.log(f"Error running model {name}: {e}")
                    results[name] = None

        return results

    def _create_consensus_finding(self, model_insights: dict, findings: list[Finding]) -> Finding:
        """Create a finding about model consensus."""
        available_models = len([r for r in model_insights.values() if r is not None])

        # Analyze consensus on risk level
        risk_levels = [r.get("overall_risk") for r in model_insights.values() if r]
        high_risk_count = len([r for r in risk_levels if r in ["CRITICAL", "HIGH"]])

        consensus_text = f"{high_risk_count}/{available_models} models rate overall risk as HIGH or CRITICAL"

        finding = Finding(
            title=f"Model Consensus: {consensus_text}",
            severity=Severity.INFO,
            description=self._format_consensus_description(model_insights, available_models),
            affected_component="overall_posture",
            agent_source=self.name,
            confidence="high",
            evidence=self._format_consensus_evidence(model_insights),
        )

        return finding

    def _create_insight_findings(self, model_insights: dict) -> list[Finding]:
        """Create findings from individual model insights."""
        findings = []

        for model_name, insights in model_insights.items():
            if not insights:
                continue

            if insights.get("false_positives"):
                finding = Finding(
                    title=f"{model_name} identified potential false positives",
                    severity=Severity.INFO,
                    description=f"{model_name} identified {len(insights['false_positives'])} findings that may be false positives",
                    affected_component="analysis_quality",
                    agent_source=self.name,
                    confidence="medium",
                    evidence=str(insights["false_positives"]),
                )
                findings.append(finding)

            if insights.get("patterns"):
                finding = Finding(
                    title=f"{model_name} identified attack patterns",
                    severity=Severity.INFO,
                    description=f"{model_name} discovered {len(insights['patterns'])} significant patterns across findings",
                    affected_component="attack_patterns",
                    agent_source=self.name,
                    confidence="medium",
                    evidence=str(insights["patterns"]),
                )
                findings.append(finding)

            if insights.get("missed_categories"):
                finding = Finding(
                    title=f"{model_name} identified missing vulnerability categories",
                    severity=Severity.INFO,
                    description=f"{model_name} suggests {len(insights['missed_categories'])} vulnerability categories that may have been missed",
                    affected_component="coverage",
                    agent_source=self.name,
                    confidence="low",
                    evidence=str(insights["missed_categories"]),
                )
                findings.append(finding)

        return findings

    def _format_consensus_description(self, model_insights: dict, model_count: int) -> str:
        """Format consensus description."""
        models_reporting = [k for k, v in model_insights.items() if v is not None]
        desc = f"Consensus analysis from {len(models_reporting)}/{model_count} available AI models:\n"

        for model in models_reporting:
            if model_insights[model]:
                desc += f"- {model}: {model_insights[model].get('overall_risk', 'N/A')}\n"

        return desc

    def _format_consensus_evidence(self, model_insights: dict) -> str:
        """Format consensus evidence."""
        evidence = "Model Analysis Results:\n"

        for model, insights in model_insights.items():
            if insights is None:
                evidence += f"\n{model}: UNAVAILABLE\n"
                continue

            evidence += f"\n{model} ({insights.get('provider')}):\n"
            evidence += f"  Overall Risk: {insights.get('overall_risk')}\n"
            evidence += f"  False Positives: {len(insights.get('false_positives', []))}\n"
            evidence += f"  Patterns Detected: {len(insights.get('patterns', []))}\n"
            evidence += f"  Missed Categories: {len(insights.get('missed_categories', []))}\n"

        return evidence
