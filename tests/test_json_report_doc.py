"""Keep the documented report keys and real example tied to the JSON renderer."""

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from agent_threat_model.cli import app

ROOT = Path(__file__).resolve().parents[1]


def test_documented_report_contract_matches_cli():
    doc = (ROOT / "docs" / "report-format.md").read_text(encoding="utf-8")
    result = CliRunner().invoke(
        app, ["analyse", str(ROOT / "examples" / "support-bot.yaml"), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    sections = {
        "Top-level fields": report,
        "Summary fields": report["summary"],
        "Finding fields": report["findings"][0],
        "Control fields": report["controls"][0],
    }
    for heading, obj in sections.items():
        section = doc.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        keys = re.findall(r"^\| `([^`]+)` \|", section, flags=re.MULTILINE)
        assert set(keys) == set(obj), heading
    example = json.loads(re.search(r"```json\n(.*?)\n```", doc, flags=re.DOTALL).group(1))
    # The example is explicitly an excerpt: one real finding, one real control,
    # plus the complete summary, with system omitted for readability.
    assert example["report_schema_version"] == report["report_schema_version"]
    assert example["tool"] == report["tool"]
    assert example["source"] == "examples/support-bot.yaml"
    assert report["source"].endswith(example["source"])
    assert example["summary"] == report["summary"]
    assert example["findings"] == report["findings"][:1]
    assert example["controls"] == report["controls"][:1]
    assert "docs/report-format.md" in (ROOT / "README.md").read_text(encoding="utf-8")
