"""`-` reads the system description from standard input."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from agent_threat_model.cli import app
from tests.conftest import EXAMPLES

runner = CliRunner()
SUPPORT = (EXAMPLES / "support-bot.yaml").read_text(encoding="utf-8")


def test_analyse_reads_stdin() -> None:
    result = runner.invoke(app, ["analyse", "-", "--format", "json"], input=SUPPORT)
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    from_file = json.loads(
        runner.invoke(
            app, ["analyse", str(EXAMPLES / "support-bot.yaml"), "--format", "json"]
        ).stdout
    )
    assert report["source"] == "<stdin>" and report["findings"] == from_file["findings"]


def test_validate_diagram_and_diff_read_stdin() -> None:
    result = runner.invoke(
        app, ["validate", "-", str(EXAMPLES / "coding-agent.yaml")], input=SUPPORT
    )
    assert result.exit_code == 0 and "ok: <stdin>" in result.stdout
    assert runner.invoke(app, ["diagram", "-"], input=SUPPORT).stdout.startswith("flowchart")
    governed = (EXAMPLES / "governed-agent.yaml").read_text(encoding="utf-8")
    result = runner.invoke(app, ["diff", str(EXAMPLES / "finance-agent.yaml"), "-"], input=governed)
    assert result.exit_code == 0 and "-> <stdin>" in result.stdout


def test_stdin_errors() -> None:
    assert runner.invoke(app, ["diff", "-", "-"]).exit_code == 2
    assert runner.invoke(app, ["validate", "-", "-"]).exit_code == 2
    result = runner.invoke(app, ["analyse", "-"], input="agents: [")
    assert result.exit_code == 2 and "<stdin> is not a valid system description" in result.output


def test_source_name_with_stdin_matches_file_sarif() -> None:
    path_str = "examples/support-bot.yaml"
    file_sarif = json.loads(
        runner.invoke(
            app, ["analyse", str(EXAMPLES / "support-bot.yaml"), "--format", "sarif"]
        ).stdout
    )
    stdin_sarif = json.loads(
        runner.invoke(
            app,
            ["analyse", "-", "--format", "sarif", "--source-name", path_str],
            input=SUPPORT,
        ).stdout
    )
    # Overwrite the expected URI to match the provided source-name for direct comparison
    for run in file_sarif.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                loc["physicalLocation"]["artifactLocation"]["uri"] = path_str
    assert stdin_sarif == file_sarif


def test_source_name_refused_with_file_argument() -> None:
    res = runner.invoke(
        app,
        ["analyse", str(EXAMPLES / "support-bot.yaml"), "--source-name", "custom.yaml"],
    )
    assert res.exit_code == 2
    assert "error: --source-name can only be used with standard input (-)" in res.output

    res_diff = runner.invoke(
        app,
        [
            "diff",
            str(EXAMPLES / "finance-agent.yaml"),
            str(EXAMPLES / "governed-agent.yaml"),
            "--source-name",
            "custom.yaml",
        ],
    )
    assert res_diff.exit_code == 2
    assert "error: --source-name can only be used with standard input (-)" in res_diff.output


def test_source_name_used_in_diff() -> None:
    governed = (EXAMPLES / "governed-agent.yaml").read_text(encoding="utf-8")
    result = runner.invoke(
        app,
        ["diff", str(EXAMPLES / "finance-agent.yaml"), "-", "--source-name", "gov-piped.yaml"],
        input=governed,
    )
    assert result.exit_code == 0
    assert "-> gov-piped.yaml" in result.stdout
