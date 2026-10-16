"""CSV report: one row per applicable threat, for risk registers and spreadsheets."""

from __future__ import annotations

import csv
import io

from agent_threat_model.engine import Analysis

CSV_COLUMNS = (
    "rank",
    "id",
    "title",
    "stride",
    "owasp_llm",
    "owasp_agentic",
    "mitre_atlas",
    "inherent_score",
    "inherent_severity",
    "residual_score",
    "residual_severity",
    "affected",
    "mitigating_controls_in_place",
    "missing_controls",
)


def _join(values: list[str]) -> str:
    return ";".join(values)


def _number(value: float) -> str:
    return f"{value:g}"


def render_csv(analysis: Analysis) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for rank, finding in enumerate(analysis.findings, start=1):
        writer.writerow(
            (
                rank,
                finding.threat_id,
                finding.title,
                finding.stride,
                _join(finding.owasp_llm),
                _join(finding.owasp_agentic),
                _join(finding.mitre_atlas),
                _number(finding.inherent),
                finding.inherent_band,
                _number(finding.residual),
                finding.residual_band,
                _join(finding.elements),
                _join(finding.mitigations_present),
                _join(finding.mitigations_missing),
            )
        )
    return buffer.getvalue()
