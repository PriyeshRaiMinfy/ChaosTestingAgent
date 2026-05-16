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

_MODEL = "claude-sonnet-4-6-20250514"
_TOOL_NAME = "record_security_analysis"

_SYSTEM_PROMPT = """\
You are a senior cloud security analyst specializing in AWS attack path analysis.

You will be given:
1. A serialized AWS dependency graph showing resources, their relationships, and network exposure
2. A list of posture findings (misconfigurations detected across the infrastructure)

Your task is to reason about real, exploitable attack paths an adversary could follow to move
from an internet-facing entry point to a high-value target (data stores, admin IAM roles, secrets).

## Analysis guidelines
- Focus on paths that chain multiple vulnerabilities together (lateral movement, privilege escalation)
- A path is only as strong as its weakest link — call out the single fix that breaks each chain
- Consider both static graph paths (network + IAM) and behavioral evidence
  (ACTUALLY_ASSUMED / ACTUALLY_ACCESSED edges = paths that have already been traversed)
- Severity:
    CRITICAL = active exploitation likely
    HIGH     = clear exploitable path exists
    MEDIUM   = requires additional conditions
    LOW      = defense-in-depth gap only
- Confidence:
    HIGH   = direct path, clear evidence
    MEDIUM = path exists but requires assumptions
    LOW    = speculative

## Output
Call the `record_security_analysis` tool exactly once with your findings.
Order attack_paths by severity (CRITICAL first). Include at most 10 paths.
Quality over quantity.
"""

_SEVERITY_ENUM = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_CONFIDENCE_ENUM = ["HIGH", "MEDIUM", "LOW"]

_ANALYSIS_TOOL: dict = {
    "name": _TOOL_NAME,
    "description": (
        "Record the structured security analysis report. Call this exactly once "
        "with the complete analysis. Do not include prose outside the tool call."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "scan_summary": {
                "type": "string",
                "description": "2-3 sentence overview of the attack surface.",
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
                            "description": "Ordered list of steps the attacker takes.",
                        },
                        "blast_radius": {
                            "type": "string",
                            "description": "What data or systems are at risk if exploited.",
                        },
                        "severity": {"type": "string", "enum": _SEVERITY_ENUM},
                        "confidence": {"type": "string", "enum": _CONFIDENCE_ENUM},
                        "remediation": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                            "description": "Specific fixes that would break this chain.",
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
    """

    def __init__(self, api_key: str | None = None) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as e:
            raise ImportError(
                "The 'anthropic' package is required for SecurityAnalyst. "
                "Install it with: pip install 'breakbot[llm]'"
            ) from e
        self._anthropic = _anthropic
        self._client = _anthropic.Anthropic(api_key=api_key) if api_key else _anthropic.Anthropic()

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
        logger.info("Sending attack surface to Claude (%s)...", _MODEL)

        with self._client.messages.stream(
            model=_MODEL,
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
