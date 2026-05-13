"""
Report data models for SecurityAnalyst output.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class AttackPath:
    entry_point: str
    attack_steps: list[str]
    blast_radius: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    confidence: str     # HIGH / MEDIUM / LOW
    remediation: list[str]

    def to_dict(self) -> dict:
        return {
            "entry_point": self.entry_point,
            "attack_steps": self.attack_steps,
            "blast_radius": self.blast_radius,
            "severity": self.severity,
            "confidence": self.confidence,
            "remediation": self.remediation,
        }


@dataclass
class AnalysisReport:
    scan_summary: str
    overall_severity: str
    attack_paths: list[AttackPath]
    top_risks: list[str]
    raw_response: str = field(repr=False, default="")

    def to_dict(self) -> dict:
        return {
            "scan_summary": self.scan_summary,
            "overall_severity": self.overall_severity,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "top_risks": self.top_risks,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines: list[str] = [
            "# BreakBot Security Analysis Report",
            "",
            f"**Overall Severity:** {self.overall_severity}",
            "",
            "## Summary",
            "",
            self.scan_summary,
        ]

        if self.top_risks:
            lines += ["", "## Top Risks", ""]
            for i, risk in enumerate(self.top_risks, 1):
                lines.append(f"{i}. {risk}")

        if self.attack_paths:
            lines += ["", "## Attack Paths", ""]
            for i, path in enumerate(self.attack_paths, 1):
                lines += [
                    f"### Path {i}: {path.entry_point} [{path.severity}]",
                    "",
                    f"**Confidence:** {path.confidence}",
                    "",
                    "**Attack Steps:**",
                ]
                for j, step in enumerate(path.attack_steps, 1):
                    lines.append(f"{j}. {step}")
                lines += [
                    "",
                    f"**Blast Radius:** {path.blast_radius}",
                ]
                if path.remediation:
                    lines += ["", "**Remediation:**"]
                    for fix in path.remediation:
                        lines.append(f"- {fix}")
                lines.append("")
        else:
            lines += ["", "*No exploitable attack paths identified.*"]

        return "\n".join(lines)
