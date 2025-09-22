\
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from .base import ParserPlugin
from ..core.models import ParsedRecord
from ..core.utils import read_text_safely, iter_lines


class TextParser(ParserPlugin):
    NAME = "text"
    SUPPORTED_EXTENSIONS = ["txt", "md", "log", "cfg", "ini", "env", "yaml", "yml", "html", "htm", "py", "js", "ts", "java", "rb", "go", "rs", "php", "cs", "c", "cpp", "h", "sh", "bash", "zsh"]

    def parse(self, path: Path) -> Iterator[ParsedRecord]:
        content = read_text_safely(path)
        if content is None:
            return
        for i, line in enumerate(iter_lines(content), start=1):
            yield ParsedRecord(file_path=path, line_num=i, text=line, context=line)


# Alias for dynamic discovery
Text = TextParser
