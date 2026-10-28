"""Seeded fuzz tests for the system reader and every command that reads a system file.

The examples are mutated at random (wrong types, missing and extra keys, duplicated elements,
empty lists, huge strings) and fed to analyse, validate, diagram and diff. Every run must end
with exit code 0, 1 or 2 and never raise. Hostile files (non-UTF-8, deep nesting, an alias
bomb, damaged YAML) must exit 2 with a message naming the file. Each test runs under an alarm.
"""

from __future__ import annotations

import copy
import random
import signal
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from agent_threat_model.cli import app
from tests.conftest import EXAMPLE_NAMES, EXAMPLES

SEED = 20261028
SECONDS = 60
runner = CliRunner()
BASES = [
    yaml.safe_load((EXAMPLES / f"{n}.yaml").read_text(encoding="utf-8")) for n in EXAMPLE_NAMES
]


@pytest.fixture(autouse=True)
def _alarm() -> Iterator[None]:
    if not hasattr(signal, "SIGALRM"):  # pragma: no cover - Windows
        yield
        return

    def fail(signum, frame):
        raise TimeoutError(f"test ran longer than {SECONDS}s")

    old = signal.signal(signal.SIGALRM, fail)
    signal.alarm(SECONDS)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _junk(rng: random.Random, depth: int) -> Any:
    options: list[Any] = [None, 5, True, "x" * rng.choice([1, 5000]), -1.5, ""]
    if depth:
        options += [
            [_junk(rng, depth - 1)],
            {rng.choice(["id", "kind", "tools", "x"]): _junk(rng, depth - 1)},
        ]
    return rng.choice(options)


def _mutate(rng: random.Random, value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            roll = rng.random()
            if roll < 0.08:
                out[key] = _junk(rng, 2)
            elif roll >= 0.12:
                out[key] = _mutate(rng, item)
        if rng.random() < 0.05:
            out[rng.choice(["id", "extra", "tools"])] = _junk(rng, 2)
        return out
    if isinstance(value, list):
        items = [_mutate(rng, item) for item in value]
        if items and rng.random() < 0.1:
            items.append(copy.deepcopy(rng.choice(items)))
        return [] if rng.random() < 0.05 else items
    return _junk(rng, 1) if rng.random() < 0.05 else value


def test_mutated_systems_never_crash(tmp_path: Path) -> None:
    rng = random.Random(SEED)
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    for _ in range(80):
        a.write_text(yaml.safe_dump(_mutate(rng, rng.choice(BASES))), encoding="utf-8")
        b.write_text(yaml.safe_dump(_mutate(rng, rng.choice(BASES))), encoding="utf-8")
        fmt = rng.choice(["table", "markdown", "json", "sarif", "html", "csv"])
        for args in (
            ["analyse", str(a), "--format", fmt],
            ["validate", str(a), str(b)],
            ["diagram", str(a)],
            ["diff", str(b), str(a), "--format", rng.choice(["table", "markdown", "json", "csv"])],
        ):
            result = runner.invoke(app, args)
            if result.exception is not None and not isinstance(result.exception, SystemExit):
                raise AssertionError(f"{args[0]} raised {result.exception!r}")
            assert result.exit_code in (0, 1, 2), args


def _alias_bomb() -> str:
    text = "a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n"
    for i in range(1, 9):
        text += f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]\n"
    return text + "system: {name: bomb}\nagents: *a8\n"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"\xff\xfesystem: x", "not UTF-8"),
        (("system: " + "[" * 100_000).encode(), "nested too deeply"),
        (b"- - -:\n", "top level must be a mapping"),
        (b"system: [unclosed\n", "invalid YAML"),
        (b"", "top level must be a mapping"),
        (_alias_bomb().encode(), "Extra inputs are not permitted"),
    ],
)
def test_hostile_files_exit_2_naming_the_file(content: bytes, message: str, tmp_path: Path) -> None:
    path = tmp_path / "system.yaml"
    path.write_bytes(content)
    for args in (["analyse", str(path)], ["validate", str(path)], ["diagram", str(path)]):
        result = runner.invoke(app, args)
        assert result.exit_code == 2, (args, result.output)
        assert str(path) in result.output and message in result.output


def test_unwritable_output_exits_2(tmp_path: Path) -> None:
    example = str(EXAMPLES / "support-bot.yaml")
    result = runner.invoke(app, ["analyse", example, "--format", "json", "-o", str(tmp_path)])
    assert result.exit_code == 2 and "cannot write" in result.output
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    result = runner.invoke(app, ["init", str(blocker / "system.yaml")])
    assert result.exit_code == 2 and "cannot write" in result.output
