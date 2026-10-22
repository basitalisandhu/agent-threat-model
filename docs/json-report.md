# JSON report contract

`atm analyse system.yaml --format json -o report.json` writes the analysis report.
It is distinct from `atm schema`, which describes the YAML input, and from
`atm diff --format json`, which reports changes between two systems.

The current `report_schema_version` is the string `"1"`, not the tool's package
version. Check it before consuming a report and handle an unfamiliar version
explicitly. Pin the tool version when reproducible catalogue content and scores
matter: the report version describes the shape, not a frozen threat catalogue.
The renderer is in `agent_threat_model/reporters/jsonout.py`; this page documents
its existing output without changing the format or version.

## Top-level fields

| Field | JSON type | Meaning |
| --- | --- | --- |
| `report_schema_version` | string | Report contract version, currently `"1"`. |
| `tool` | object | `name` (`"agent-threat-model"`) and `version` (package version), both strings. |
| `source` | string | Input path as passed to the analysis; no timestamp or file contents. |
| `system` | object | Validated input model, including default values; see [input format](input-format.md) and [input schema](../schema/system.schema.json). |
| `summary` | object | Aggregate counts and scores described below. |
| `findings` | array of objects | Applicable threats only, in ranked order; empty when no threats apply. |
| `controls` | array of objects | Controls relevant to findings plus explicitly declared controls, sorted by id. |

## Summary fields

| Field | JSON type | Meaning |
| --- | --- | --- |
| `findings` | integer | Number of entries in the top-level `findings` array. |
| `residual_bands` | object | Counts after mitigation under `critical`, `high`, `medium`, `low`; all four keys are present. |
| `inherent_bands` | object | Counts before mitigation under the same four band keys. |
| `inherent_total` | number | Sum of inherent severities of applicable findings. |
| `residual_total` | number | Sum of residual severities, rounded to one decimal place. |
| `baseline_total` | number | Inherent total when the same system is analysed with no controls declared; it can include threats removed by the current controls. |
| `residual_risk_score` | integer | Rounded `100 * residual_total / baseline_total`, clamped to 0..100; 0 when the baseline is zero. |
| `rating` | string | Score band: `critical` at 75+, `high` at 50+, `medium` at 25+, otherwise `low`. |
| `reduction_percent` | integer | `max(0, 100 - residual_risk_score)`. |

The score is modelled residual risk relative to the no-controls baseline, not
the probability of an incident or a compliance assessment. Severity bands for
individual findings use different thresholds from the summary rating.

## Finding fields

| Field | JSON type | Meaning |
| --- | --- | --- |
| `threat_id` | string | Catalogue threat id; use this, not rank, to identify the threat across reports. |
| `title` | string | Catalogue title. |
| `description` | string | What goes wrong and who can cause it. |
| `stride` | string | STRIDE category as a lower-case kebab-case value. |
| `owasp_llm` | array of strings | OWASP LLM ids; may be empty. |
| `owasp_agentic` | array of strings | OWASP Agentic ids; may be empty. |
| `mitre_atlas` | array of strings | MITRE ATLAS technique ids; may be empty. |
| `rule` | string | Catalogue predicate expression that matched. |
| `likelihood` | integer | Catalogue likelihood, 1..5. |
| `impact` | integer | Impact used for scoring, 1..5, including any regulated-data adjustment. |
| `impact_adjusted` | boolean | Whether the regulated-data adjustment raised impact. |
| `inherent` | integer | Likelihood multiplied by impact, before mitigation. |
| `elements` | array of strings | Input element ids implicated by the matched rule. |
| `reasons` | array of strings | Human-readable explanations of the match. |
| `mitigations_present` | array of strings | Applicable control ids declared in the input. |
| `mitigations_missing` | array of strings | Applicable control ids not declared in the input. |
| `coverage` | number | Weighted fraction of the threat's mitigations present, 0..1, rounded to three decimal places. |
| `residual` | number | `inherent * (1 - 0.8 * coverage)` using unrounded coverage, rounded to one decimal place; a floor of 20% of inherent. |
| `references` | array of strings | Catalogue reference URLs; may be empty. |
| `rank` | integer | One-based position in this report. |
| `inherent_band` | string | `critical` at 20+, `high` at 12+, `medium` at 6+, otherwise `low`. |
| `residual_band` | string | Same severity thresholds, applied to residual severity. |

Findings sort by descending residual, then descending inherent, then ascending
`threat_id`. Adding a control can change ranks or remove a finding entirely.
An empty mapping array means no mapping is supplied, not proof that no framework
entry applies.

## Control fields

| Field | JSON type | Meaning |
| --- | --- | --- |
| `id` | string | Catalogue control id, referenced by finding mitigation arrays. |
| `title` | string | Catalogue control title. |
| `type` | string | `preventive`, `detective` or `corrective`. |
| `effort` | string | `low`, `medium` or `high`. |
| `present` | boolean | Whether the input declares this control; not a verification of its implementation. |
| `threats` | array of strings | Applicable threat ids this control mitigates; empty for a declared control irrelevant to current findings. |

## Example excerpt

Run this command from the repository root to get the complete report:

```sh
atm analyse examples/support-bot.yaml --format json -o support-bot.json
```

This is an excerpt of that report, not a complete report: `tool`, `source` and
`system` are omitted and only the first finding and control are shown. The
summary still describes all 21 findings, and `tests/test_json_report_doc.py`
checks these values against the actual CLI output.

```json
{
  "report_schema_version": "1",
  "summary": {
    "findings": 21,
    "residual_bands": {"critical": 0, "high": 14, "medium": 7, "low": 0},
    "inherent_bands": {"critical": 0, "high": 14, "medium": 7, "low": 0},
    "inherent_total": 241.0,
    "residual_total": 238.6,
    "baseline_total": 241.0,
    "residual_risk_score": 99,
    "rating": "critical",
    "reduction_percent": 1
  },
  "findings": [
    {
      "threat_id": "excessive-agency",
      "title": "Excessive agency on write, exec or payment tools",
      "description": "An agent that may act on its own can call a tool with side effects without any approval step. One wrong inference, one injected instruction or one hallucinated argument becomes a real-world action.",
      "stride": "elevation-of-privilege",
      "owasp_llm": ["LLM06"],
      "owasp_agentic": ["ASI02", "ASI03"],
      "mitre_atlas": ["AML.T0053"],
      "rule": "tool_kind_without_approval(kinds=write|exec|payment)",
      "likelihood": 4,
      "impact": 4,
      "impact_adjusted": false,
      "inherent": 16,
      "elements": ["create-ticket", "support-bot"],
      "reasons": [
        "agent 'support-bot' (act) can call tool 'create-ticket' (write) with approval: none"
      ],
      "mitigations_present": [],
      "mitigations_missing": [
        "approval-gates",
        "runtime-policy-enforcement",
        "least-privilege-tool-scopes",
        "audit-log",
        "kill-switch"
      ],
      "coverage": 0.0,
      "residual": 16.0,
      "references": [
        "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM06_ExcessiveAgency.md"
      ],
      "rank": 1,
      "inherent_band": "high",
      "residual_band": "high"
    }
  ],
  "controls": [
    {
      "id": "adversarial-testing",
      "title": "Adversarial testing before and after release",
      "type": "detective",
      "effort": "medium",
      "present": false,
      "threats": [
        "direct-prompt-injection",
        "hallucinated-actions",
        "supply-chain-unpinned",
        "system-prompt-leakage"
      ]
    }
  ]
}
```

## Consumer guidance

Accept JSON numbers rather than relying on an integer or decimal spelling of a
score. Do not treat object key order as meaningful, and join findings and
controls by their ids rather than array positions.

Output is deterministic for the same system, source path, catalogue and tool
version, with a trailing newline and no generated timestamp. Different input
paths change `source`, even if their file contents match.
