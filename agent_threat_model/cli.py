"""Command line interface: ``atm`` and ``agent-threat-model``.

from __future__ import annotations

import csv
import io
import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agent_threat_model import __version__
from agent_threat_model.catalogue import EFFORT_ORDER, load_catalogue
from agent_threat_model.diagram import mermaid
from agent_threat_model.diff import Diff, diff_analyses
from agent_threat_model.engine import BAND_ORDER, Analysis, analyse
from agent_threat_model.loader import (
    STDIN,
    SystemLoadError,
    load_system,
    read_source,
    system_from_text,
)
from agent_threat_model.reporters import render
from agent_threat_model.reporters.table import HAVE_RICH, print_rich
from agent_threat_model.schema import json_schema
from agent_threat_model.template import TEMPLATE
