"""Load and validate a system description from YAML."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_threat_model.catalogue import Catalogue, load_catalogue
from agent_threat_model.schema import AgentSystem


class SystemLoadError(ValueError):
    """Raised when a system file cannot be parsed or validated."""

    def __init__(self, source: str, problems: list[str]):
        self.source = source
        self.problems = problems
        super().__init__(f"{source}: " + "; ".join(problems))


def format_validation_error(error: ValidationError) -> list[str]:
    lines: list[str] = []
    for item in error.errors():
        location = ".".join(str(p) for p in item["loc"]) or "<root>"
        message = item["msg"]
        if message.startswith("Value error, "):
            message = message[len("Value error, ") :]
        lines.append(f"{location}: {message}")
    return lines


def system_from_dict(
    data: Any, source: str = "<dict>", catalogue: Catalogue | None = None
) -> AgentSystem:
    if not isinstance(data, dict):
        raise SystemLoadError(source, ["top level must be a mapping with a 'system' key"])
    try:
        system = AgentSystem.model_validate(data)
    except ValidationError as error:
        raise SystemLoadError(source, format_validation_error(error)) from error
    catalogue = catalogue or load_catalogue()
    unknown = [c for c in system.controls if c not in catalogue.controls]
    if unknown:
        raise SystemLoadError(
            source,
            [f"controls: unknown control id '{c}' (see 'atm catalogue controls')" for c in unknown],
        )
    return system


STDIN = "-"


def read_source(path: Path | str) -> tuple[str, str]:
    """Return ``(text, source name)`` for a file, or for standard input when ``path`` is ``-``."""
    from_stdin = str(path) == STDIN
    source = "<stdin>" if from_stdin else str(path)
    try:
        data = sys.stdin.buffer.read() if from_stdin else Path(path).read_bytes()
    except OSError as error:
        raise SystemLoadError(source, [f"cannot read file: {error.strerror}"]) from error
    try:
        return data.decode("utf-8"), source
    except UnicodeDecodeError as error:
        raise SystemLoadError(
            source, [f"not UTF-8 text (byte {error.start}); save the file as UTF-8"]
        ) from error


def load_system(path: Path | str, catalogue: Catalogue | None = None) -> AgentSystem:
    """Read a YAML file, or standard input for ``-``, and return an :class:`AgentSystem`."""
    text, source = read_source(path)
    return system_from_text(text, source, catalogue)


def system_from_text(
    text: str, source: str = "<text>", catalogue: Catalogue | None = None
) -> AgentSystem:
    """Parse YAML text and return a validated :class:`AgentSystem`."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise SystemLoadError(source, [f"invalid YAML: {error}"]) from error
    except RecursionError as error:
        raise SystemLoadError(source, ["invalid YAML: nested too deeply to read"]) from error
    return system_from_dict(data, source, catalogue)
