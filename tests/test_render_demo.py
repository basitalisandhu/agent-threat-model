"""docs/demo.svg, the README demo, regenerates from the committed examples with
scripts/render_demo.py.

The test renders into a temporary file and checks the result is well-formed SVG holding the command
and one line of its real output. It does not compare bytes with the committed SVG, so it stays
stable across platforms.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "render_demo.py"
SVG_NS = "{http://www.w3.org/2000/svg}"
COMMAND = "atm analyse examples/support-bot.yaml --plain"
EXPECTED = "Residual risk score: 90 (critical) -> 27 (medium), change -63"


def svg_text(path: Path) -> str:
    """All text in the SVG, with the renderer's no-break spaces turned back into spaces."""
    root = ET.parse(path).getroot()
    assert root.tag == f"{SVG_NS}svg"
    return "\n".join("".join(t.itertext()) for t in root.iter(f"{SVG_NS}text")).replace(
        "\u00a0", " "
    )


def test_render_demo_regenerates_a_well_formed_svg(tmp_path: Path) -> None:
    out = tmp_path / "demo.svg"
    argv = [sys.executable, str(SCRIPT), "--output", str(out)]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr
    text = svg_text(out)
    assert f"$ {COMMAND}" in text
    assert EXPECTED in text
    assert str(ROOT) not in text


def test_committed_demo_is_well_formed_and_shows_the_command() -> None:
    assert f"$ {COMMAND}" in svg_text(ROOT / "docs" / "demo.svg")
