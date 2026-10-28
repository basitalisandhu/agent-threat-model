"""Scaling check: ten times the system must take roughly ten times as long, not a hundred.

The support-bot example is copied 5 and 50 times over with renamed ids (so every copy is a
separate set of agents, channels, tools and stores) and analysed in every format, diffed and
drawn. The ratio of the two timings (best of three) must stay under 30.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_threat_model.cli import app
from tests.conftest import EXAMPLES

LIMIT = 30
FIXED = {
    "description",
    "name",
    "kind",
    "trust",
    "autonomy",
    "memory",
    "origin",
    "auth",
    "model_provider",
}


def _scaled(copies: int) -> dict[str, Any]:
    base = yaml.safe_load((EXAMPLES / "support-bot.yaml").read_text(encoding="utf-8"))
    ids = {x["id"] for v in base.values() if isinstance(v, list) for x in v if isinstance(x, dict)}

    def rename(value: Any, i: int) -> Any:
        if isinstance(value, str):
            return f"{value}-{i}" if value in ids else value
        if isinstance(value, list):
            return [rename(v, i) for v in value]
        if isinstance(value, dict):
            return {k: (v if k in FIXED else rename(v, i)) for k, v in value.items()}
        return value

    out = {k: v for k, v in base.items() if not isinstance(v, list) or k == "controls"}
    for key, value in base.items():
        if isinstance(value, list) and key != "controls":
            out[key] = [rename(item, i) for i in range(copies) for item in value]
    return out


def _best(fn: Callable[[], object]) -> float:
    times = []
    for _ in range(3):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return max(min(times), 1e-3)


@pytest.mark.parametrize("command", ["json", "sarif", "markdown", "html", "csv", "diff", "diagram"])
def test_ten_times_the_system_stays_near_linear(command: str, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    runner = CliRunner()
    timings = []
    for copies in (5, 50):
        path = tmp_path / f"system-{copies}.yaml"
        path.write_text(yaml.safe_dump(_scaled(copies), sort_keys=False), encoding="utf-8")
        if command == "diff":
            args = ["diff", str(path), str(path)]
        elif command == "diagram":
            args = ["diagram", str(path)]
        else:
            args = ["analyse", str(path), "--format", command]
        assert runner.invoke(app, args).exit_code == 0
        timings.append(_best(lambda a=args: runner.invoke(app, a)))
    small, large = timings
    assert large / small < LIMIT, f"{command}: 5 copies {small:.3f}s, 50 copies {large:.3f}s"
