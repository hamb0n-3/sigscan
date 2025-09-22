\
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class ParsedRecord:
    file_path: Path
    line_num: int
    text: str
    context: str = ""  # the whole line or logical fragment


@dataclass
class Finding:
    secret: Optional[str]  # for generality, "secret" field is used by secrets plugin (required in secrets.json)
    context: str
    line_num: int
    file_location: str  # string path for JSON serializable output
    category: str
    meta: Dict[str, Any] = field(default_factory=dict)


class PluginState:
    """Per-plugin runtime state."""
    pass
