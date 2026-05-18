"""
SecurityAnalyst — LLM-powered attack-path analysis using Claude.

Takes the serialized graph text (from GraphSerializer) and posture findings
(from PostureAnalyzer) and produces a structured threat report.

Schema enforcement: we use Claude's tool-use feature with a forced tool_choice.
The API validates the model's output against the tool's input_schema before
returning, so we never have to parse free-form JSON or strip code fences.

Usage:
    analyst = SecurityAnalyst()
    report = analyst.analyze(attack_surface_text, posture_findings)
    print(report.to_markdown())
"""
from __future__ import annotations

import json
import logging
from typing import Sequence

from breakbot.brain.report import AnalysisReport, AttackPath

logger = logging.getLogger(__name__)

_MODEL = "apac.anthropic.claude-sonnet-4-20250514-v1:0"
_DIRECT_MODEL = "claude-sonnet-4-6-20250514"
_TOOL_NAME = "record_security_analysis"

_SYSTEM_PROMPT = """\
You are a penetration tester writing a findings report after scanning a live AWS environment.
You have the resource graph and misconfiguration list. Write like you actually looked at this infrastructure — direct, specific, no filler.

Rules:
- Name the actual resources. Don't say "an S3 bucket" when you know it's "mahaveer0602".
- Attack steps should read like a real procedure: what you'd type, what you'd click, what you'd get.
- Blast radius: be concrete. "Access to all DynamoDB tables including patient-records and audit-logs" beats "data exfiltration risk".
- Remediation: one specific action per item. Not "follow best practices" — the exact fix.
- scan_summary: 2-3 sentences. What's the worst thing in this environment and why.
- top_risks: plain bullets, no corporate language. What would you tell the dev team in a standup?
- Skip paths that don't actually lead anywhere. If a public bucket has nothing sensitive, don't hype it.
- ACTUALLY_ASSUMED / ACTUALLY_ACCESSED edges in the graph = this path was already traversed. Flag those.

Severity:
  CRITICAL = exploitable right now, no assumptions needed
  HIGH     = one small step away from exploitable
  MEDIUM   = needs extra conditions
  LOW      = hygiene gap, low real-world impact

Confidence:
  HIGH   = direct evidence in graph
  MEDIUM = reasonable assumption
  LOW    = speculative

Call record_security_analysis once. Max 10 paths, best ones only.
"""

_SEVERITY_ENUM = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_CONFIDENCE_ENUM = ["HIGH", "MEDIUM", "LOW"]

_ANALYSIS_TOOL: dict = {
    "name": _TOOL_NAME,
    "description": (
        "Record the security findings. Be specific — use actual resource names from the graph. "
        "Write like a pentester, not a compliance report. Call exactly once."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "scan_summary": {
                "type": "string",
                "description": "2-3 sentences. State the worst issue and why it matters. Name actual resources. No fluff.",
            },
            "overall_severity": {
                "type": "string",
                "enum": _SEVERITY_ENUM,
                "description": "Highest severity across all attack paths.",
            },
            "attack_paths": {
                "type": "array",
                "maxItems": 10,
                "description": "Attack paths ordered by severity (CRITICAL first).",
                "items": {
                    "type": "object",
                    "properties": {
                        "entry_point": {
                            "type": "string",
                            "description": "Resource name or ARN where the attacker starts.",
                        },
                        "attack_steps": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                            "description": "Ordered steps. Concrete actions: curl commands, aws cli calls, what you'd actually do. Name the real resources.",
                        },
                        "blast_radius": {
                            "type": "string",
                            "description": "What specifically breaks. Name the tables, buckets, roles at risk. One sentence.",
                        },
                        "severity": {"type": "string", "enum": _SEVERITY_ENUM},
                        "confidence": {"type": "string", "enum": _CONFIDENCE_ENUM},
                        "remediation": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                            "description": "Exact fixes. Not 'improve IAM policies' — the specific action: which role, which permission to remove, which setting to toggle.",
                        },
                    },
                    "required": [
                        "entry_point",
                        "attack_steps",
                        "blast_radius",
                        "severity",
                        "confidence",
                        "remediation",
                    ],
                    "additionalProperties": False,
                },
            },
            "top_risks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Highest-priority findings, plain language.",
            },
        },
        "required": ["scan_summary", "overall_severity", "attack_paths", "top_risks"],
        "additionalProperties": False,
    },
}


class SecurityAnalyst:
    """
    Calls Claude to reason over the serialized attack surface and produce
    a structured threat report. Schema is enforced server-side via tool use.

    Supports two backends:
      - AWS Bedrock (default): uses AWS credentials from environment/profile
      - Direct Anthropic API: set ANTHROPIC_API_KEY env var
    """

    def __init__(self, api_key: str | None = None, use_bedrock: bool = True, region: str = "ap-south-1") -> None:
        try:
            import anthropic as _anthropic
        except ImportError as e:
            raise ImportError(
                "The 'anthropic' package is required for SecurityAnalyst. "
                "Install it with: pip install 'breakbot[llm]'"
            ) from e
        self._anthropic = _anthropic

        if api_key or not use_bedrock:
            self._client = _anthropic.Anthropic(api_key=api_key) if api_key else _anthropic.Anthropic()
            self._model = _DIRECT_MODEL
        else:
            self._client = _anthropic.AnthropicBedrock(aws_region=region)
            self._model = _MODEL

    def analyze(
        self,
        attack_surface: str,
        posture_findings: Sequence[dict],
    ) -> AnalysisReport:
        """
        Args:
            attack_surface:   Output of GraphSerializer.serialize()
            posture_findings: List of PostureFinding.to_dict() dicts
        Returns:
            AnalysisReport — guaranteed to match the tool schema
        """
        user_message = _build_user_message(attack_surface, posture_findings)
        logger.info("Sending attack surface to Claude (%s)...", self._model)

        with self._client.messages.stream(
            model=self._model,
            max_tokens=8192,
            tools=[_ANALYSIS_TOOL],
            tool_choice={"type": "tool", "name": _TOOL_NAME},
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        ) as stream:
            message = stream.get_final_message()

        if message.stop_reason != "tool_use":
            raise RuntimeError(
                f"Expected stop_reason='tool_use', got '{message.stop_reason}'. "
                f"Model may have hit max_tokens or encountered an error."
            )

        tool_input = _extract_tool_input(message)
        return _build_report(tool_input)


def _build_user_message(attack_surface: str, posture_findings: Sequence[dict]) -> str:
    lines = ["## ATTACK SURFACE GRAPH\n", attack_surface, "\n"]

    if posture_findings:
        lines.append("## POSTURE FINDINGS\n")
        by_severity: dict[str, list[dict]] = {}
        for f in posture_findings:
            sev = f.get("severity", "INFO")
            by_severity.setdefault(sev, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            group = by_severity.get(sev, [])
            if not group:
                continue
            lines.append(f"\n### {sev} ({len(group)})\n")
            for f in group:
                lines.append(
                    f"- [{f['check_id']}] {f['title']}\n"
                    f"  Resource: {f['resource_name']} ({f['resource_type']})\n"
                    f"  Detail: {f['detail']}\n"
                    f"  Fix: {f['remediation']}\n"
                )
    else:
        lines.append("## POSTURE FINDINGS\n(none)\n")

    return "".join(lines)


def _extract_tool_input(message: object) -> dict:
    """
    Find the single tool_use block in the response and return its validated
    input dict. With tool_choice forcing our tool, the API guarantees exactly
    one tool_use block with input matching the schema.
    """
    for block in message.content:  # type: ignore[union-attr]
        if block.type == "tool_use" and block.name == _TOOL_NAME:
            return dict(block.input)
    raise RuntimeError(
        f"Claude did not invoke the '{_TOOL_NAME}' tool. "
        f"Response blocks: {[b.type for b in message.content]}"  # type: ignore[union-attr]
    )


def _build_report(tool_input: dict) -> AnalysisReport:
    """
    Build an AnalysisReport from validated tool input. No defaults needed —
    the schema enforces every required field before we get here.
    """
    paths = [
        AttackPath(
            entry_point=p["entry_point"],
            attack_steps=list(p["attack_steps"]),
            blast_radius=p["blast_radius"],
            severity=p["severity"],
            confidence=p["confidence"],
            remediation=list(p["remediation"]),
        )
        for p in tool_input["attack_paths"]
    ]
    return AnalysisReport(
        scan_summary=tool_input["scan_summary"],
        overall_severity=tool_input["overall_severity"],
        attack_paths=paths,
        top_risks=list(tool_input["top_risks"]),
        raw_response=json.dumps(tool_input, indent=2),
    )
