\
from __future__ import annotations
import json
from pathlib import Path
from typing import Iterator, Any, Dict, List
from .base import ParserPlugin
from ..core.models import ParsedRecord
from ..core.utils import read_text_safely


def _flatten_json(obj: Any, path: List[str], out: List[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten_json(v, path + [str(k)], out)
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            _flatten_json(v, path + [str(idx)], out)
    else:
        flat_path = ".".join(path)
        out.append(f"{flat_path}: {obj}")


class JSONParser(ParserPlugin):
    NAME = "json"
    SUPPORTED_EXTENSIONS = ["json"]

    def parse(self, path: Path) -> Iterator[ParsedRecord]:
        content = read_text_safely(path)
        if content is None:
            return
        try:
            data = json.loads(content)
            flattened: List[str] = []
            _flatten_json(data, [], flattened)
            for i, line in enumerate(flattened, start=1):
                yield ParsedRecord(file_path=path, line_num=i, text=line, context=line)
        except Exception:
            # fallback to line-by-line
            for i, line in enumerate(content.splitlines(), start=1):
                yield ParsedRecord(file_path=path, line_num=i, text=line, context=line)


JSON = JSONParser
