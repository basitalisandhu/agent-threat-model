"""End-to-end: build the wheel, install it in a fresh venv and run the README 30-second demo.

The demo block is run as written, with `pipx install` replaced by installing the freshly built
wheel; every line of the README output excerpt (except the `...` elision) must appear in the
real `--plain` output, which is the form the README shows. Then the "full report" and the
`atm diff` example run against a copy of examples/.
Building needs the network for the build backend and dependencies, so this runs only when
ATM_E2E=1; CI sets it in the quickstart job.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from tests.conftest import ROOT

pytestmark = pytest.mark.skipif(os.environ.get("ATM_E2E") != "1", reason="set ATM_E2E=1 to run")

README = (ROOT / "README.md").read_text(encoding="utf-8")


def _section() -> str:
    start = README.index("## 30-second demo")
    return README[start : README.index("\n## ", start + 5)]


@pytest.fixture(scope="module")
def bin_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("e2e")
    dist = base / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist), str(ROOT)],
        check=True,
        capture_output=True,
    )
    venv.create(base / "venv", with_pip=True)
    bin_dir = base / "venv" / ("Scripts" if os.name == "nt" else "bin")
    wheel = next(dist.glob("agent_threat_model-*.whl"))
    subprocess.run(
        [str(bin_dir / "python"), "-m", "pip", "install", "-q", str(wheel)],
        check=True,
        capture_output=True,
    )
    return bin_dir


def _bash(script: str, cwd: Path, bin_dir: Path) -> str:
    env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin", "LC_ALL": "C.UTF-8", "COLUMNS": "200"}
    proc = subprocess.run(
        ["bash", "-c", script], cwd=cwd, env=env, capture_output=True, text=True, check=True
    )
    return proc.stdout


def test_readme_demo(bin_dir: Path, tmp_path: Path) -> None:
    blocks = re.findall(r"```(bash|text)\n(.*?)```", _section(), re.S)
    demo, excerpt, report = blocks[0][1], blocks[1][1], blocks[2][1]
    lines = [line.split("  #")[0].strip() for line in demo.splitlines()]
    assert lines[0].startswith("pipx install ")
    out = _bash("\n".join(lines[1:]), tmp_path, bin_dir)
    assert "Threat model: Customer support assistant" in out
    # The excerpt is the --plain form of the same table (the README says so).
    plain = _bash(lines[-1] + " --plain", tmp_path, bin_dir)
    got = [line.rstrip() for line in plain.splitlines()]
    missing = [line for line in excerpt.splitlines() if line != "..." and line.rstrip() not in got]
    assert missing == [], missing
    _bash(report.split("  #")[0].strip(), tmp_path, bin_dir)
    assert (tmp_path / "threat-model.md").read_text(encoding="utf-8").startswith("# Threat model")


def test_readme_diff(bin_dir: Path, tmp_path: Path) -> None:
    shutil.copytree(ROOT / "examples", tmp_path / "examples")
    block = re.search(r"```bash\n\$ (atm diff .*?)\n(.*?)```", _section(), re.S)
    assert block
    out = _bash(block.group(1), tmp_path, bin_dir)
    expected = [line for line in block.group(2).splitlines() if line.strip() != "..."]
    assert [line for line in expected if line not in out.splitlines()] == []


def test_installed_command_reads_stdin(bin_dir: Path) -> None:
    yaml_text = (ROOT / "examples" / "support-bot.yaml").read_text(encoding="utf-8")
    proc = subprocess.run(
        [str(bin_dir / "atm"), "validate", "-"], input=yaml_text, capture_output=True, text=True
    )
    assert proc.returncode == 0 and proc.stdout.startswith("ok: <stdin>")
