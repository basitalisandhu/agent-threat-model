import csv
import io
import json

import pytest
from typer.testing import CliRunner

from agent_threat_model.cli import app
from agent_threat_model.diff import diff_analyses
from agent_threat_model.engine import analyse
from agent_threat_model.loader import load_system
from tests.conftest import build


def test_diff_detects_added_threat(analysed):
    before = analysed()
    data = build()
    data["tools"].append(
        {
            "id": "sh",
            "kind": "exec",
            "auth": "none",
            "sandboxed": False,
            "pinned": True,
            "scope": "narrow",
        }
    )
    data["agents"][0]["tools"].append("sh")
    after = analysed(**data)
    diff = diff_analyses(before, after)
    assert "unsandboxed-exec" in {f.threat_id for f in diff.added}
    assert not diff.removed
    assert diff.score_delta >= 0
    assert not diff.is_empty


def test_diff_detects_removed_threat_and_controls(analysed):
    before = analysed()
    after = analysed(controls=["audit-log", "kill-switch"])
    diff = diff_analyses(before, after)
    removed = {f.threat_id for f in diff.removed}
    assert {"missing-audit-trail", "missing-kill-switch"} <= removed
    assert diff.controls_added == ["audit-log", "kill-switch"]
    assert diff.new_score < diff.old_score


def test_diff_reports_mitigation_changes(analysed):
    before = analysed()
    after = analysed(controls=["rate-limiting"])
    diff = diff_analyses(before, after)
    assert "no-rate-limits" in {f.threat_id for f in diff.removed}
    change = next(c for c in diff.changed if c.threat_id == "denial-of-wallet")
    assert change.mitigations_now_present == ["rate-limiting"]
    assert change.new_residual < change.old_residual
    assert change.delta < 0


def test_identical_systems_produce_empty_diff(analysed):
    diff = diff_analyses(analysed(), analysed())
    assert diff.is_empty
    assert diff.unchanged == len(analysed().findings)


def test_example_diff_finance_to_governed(example_path):
    old = analyse(load_system(example_path("finance-agent")), source="finance")
    new = analyse(load_system(example_path("governed-agent")), source="governed")
    diff = diff_analyses(old, new)
    assert diff.score_delta < -30
    assert "brokered-credentials" in diff.controls_added
    assert {"static-long-lived-credentials", "missing-audit-trail"} <= {
        f.threat_id for f in diff.removed
    }


CSV_HEADER = [
    "change",
    "id",
    "title",
    "old_residual",
    "new_residual",
    "old_severity",
    "new_severity",
]


@pytest.mark.parametrize(
    ("old", "new"),
    [("finance-agent", "governed-agent"), ("governed-agent", "finance-agent")],
)
def test_diff_csv_matches_json(example_path, old, new):
    runner = CliRunner()
    args = ["diff", str(example_path(old)), str(example_path(new))]
    result = runner.invoke(app, [*args, "--format", "csv"])
    json_result = runner.invoke(app, [*args, "--format", "json"])
    assert result.exit_code == json_result.exit_code == 0
    assert result.stdout.splitlines()[0] == ",".join(CSV_HEADER)
    reader = csv.DictReader(io.StringIO(result.stdout))
    rows = list(reader)
    assert reader.fieldnames == CSV_HEADER
    payload = json.loads(json_result.stdout)
    assert payload["removed" if old == "finance-agent" else "added"]
    expected = []
    for change, key in [("added", "added"), ("removed", "removed")]:
        for finding in payload[key]:
            expected.append(
                {
                    "change": change,
                    "id": finding["threat_id"],
                    "title": finding["title"],
                    "old_residual": f"{finding['residual']:g}" if change == "removed" else "",
                    "new_residual": f"{finding['residual']:g}" if change == "added" else "",
                    "old_severity": finding["residual_band"] if change == "removed" else "",
                    "new_severity": finding["residual_band"] if change == "added" else "",
                }
            )
    assert payload["changed"]
    for finding in payload["changed"]:
        expected.append(
            {
                "change": "rescored",
                "id": finding["threat_id"],
                "title": finding["title"],
                "old_residual": f"{finding['old_residual']:g}",
                "new_residual": f"{finding['new_residual']:g}",
                "old_severity": finding["old_band"],
                "new_severity": finding["new_band"],
            }
        )
    assert rows == expected


def test_diff_csv_identical_systems_writes_header_only(example_path, tmp_path):
    output = tmp_path / "diff.csv"
    path = str(example_path("finance-agent"))
    result = CliRunner().invoke(
        app, ["diff", path, path, "--format", "csv", "--output", str(output)]
    )
    assert result.exit_code == 0
    assert list(csv.reader(io.StringIO(output.read_text()))) == [CSV_HEADER]
