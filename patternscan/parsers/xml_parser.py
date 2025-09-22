\
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET
from .base import ParserPlugin
from ..core.models import ParsedRecord
from ..core.utils import read_text_safely


def _iter_elements(e, path=""):
    tag = e.tag if isinstance(e.tag, str) else "unknown"
    current = f"{path}/{tag}" if path else f"/{tag}"
    text = (e.text or "").strip()
    if text:
        yield current, text
    for child in e:
        yield from _iter_elements(child, current)


class XMLParser(ParserPlugin):
    NAME = "xml"
    SUPPORTED_EXTENSIONS = ["xml"]

    def parse(self, path: Path) -> Iterator[ParsedRecord]:
        content = read_text_safely(path)
        if content is None:
            return
        try:
            root = ET.fromstring(content)
            i = 0
            for xpath, text in _iter_elements(root):
                i += 1
                line = f"{xpath}: {text}"
                yield ParsedRecord(file_path=path, line_num=i, text=line, context=line)
        except Exception:
            # fallback to line-by-line
            for i, line in enumerate(content.splitlines(), start=1):
                yield ParsedRecord(file_path=path, line_num=i, text=line, context=line)


XML = XMLParser
