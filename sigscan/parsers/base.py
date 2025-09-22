\
from __future__ import annotations
from pathlib import Path
from typing import Iterable, Iterator, List
from ..core.models import ParsedRecord
from ..core.utils import read_text_safely, iter_lines


class ParserPlugin:
    NAME = "base"
    SUPPORTED_EXTENSIONS: List[str] = []  # override in subclasses

    def parse(self, path: Path) -> Iterator[ParsedRecord]:
        raise NotImplementedError("parse must be implemented in subclasses")
