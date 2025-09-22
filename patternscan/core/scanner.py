\
from __future__ import annotations
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .utils import read_text_safely, iter_lines
from .models import ParsedRecord
from ..parsers.base import ParserPlugin
from ..patterns.base import PatternPlugin


def _choose_parser(parser_plugins: Dict[str, ParserPlugin], path: Path) -> ParserPlugin:
    ext = path.suffix.lower().lstrip(".")
    for plugin in parser_plugins.values():
        if ext in plugin.SUPPORTED_EXTENSIONS:
            return plugin
    # fallback to text parser
    return parser_plugins.get("text", next(iter(parser_plugins.values())))


class DirectoryScanner:
    def __init__(
        self,
        root: Path,
        parser_plugins: Dict[str, ParserPlugin],
        pattern_plugins: Dict[str, PatternPlugin],
        include_globs: List[str],
        exclude_dirs: List[str],
        max_file_size: int = 5_000_000,
        workers: int = 8,
    ) -> None:
        self.root = root
        self.parser_plugins = parser_plugins
        self.pattern_plugins = pattern_plugins
        self.include_globs = include_globs
        self.exclude_dirs = set(exclude_dirs)
        self.max_file_size = max_file_size
        self.workers = workers

    def _iter_files(self) -> Iterator[Path]:
        for p in self.root.rglob("*"):
            if p.is_dir():
                # skip dir names in exclude list
                if p.name in self.exclude_dirs:
                    # skip traversal into excluded dirs by not yielding anything
                    continue
                else:
                    continue
            if any(fnmatch.fnmatch(p.name, pat) for pat in self.include_globs):
                try:
                    if p.stat().st_size <= self.max_file_size:
                        yield p
                except Exception:
                    continue

    def scan(self) -> None:
        # Init pattern plugins
        for plugin in self.pattern_plugins.values():
            plugin.begin()

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self._scan_file, path): path for path in self._iter_files()}
            for f in as_completed(futures):
                _ = futures[f]
                # swallow exceptions but keep scanning
                try:
                    f.result()
                except Exception as e:
                    # Could log
                    pass

        for plugin in self.pattern_plugins.values():
            plugin.end()

    def _scan_file(self, path: Path) -> None:
        parser = _choose_parser(self.parser_plugins, path)
        try:
            for plugin in self.pattern_plugins.values():
                plugin.begin_file(path)
            for record in parser.parse(path):
                for plugin in self.pattern_plugins.values():
                    plugin.process_record(record)
            for plugin in self.pattern_plugins.values():
                plugin.end_file(path)
        except Exception:
            # best-effort scanning
            for plugin in self.pattern_plugins.values():
                plugin.end_file(path)


class SingleFileScanner:
    def __init__(
        self,
        file_path: Path,
        parser_plugins: Dict[str, ParserPlugin],
        pattern_plugins: Dict[str, PatternPlugin],
    ) -> None:
        self.file_path = file_path
        self.parser_plugins = parser_plugins
        self.pattern_plugins = pattern_plugins

    def scan(self) -> None:
        for plugin in self.pattern_plugins.values():
            plugin.begin()
            plugin.begin_file(self.file_path)
        parser = _choose_parser(self.parser_plugins, self.file_path)
        for rec in parser.parse(self.file_path):
            for plugin in self.pattern_plugins.values():
                plugin.process_record(rec)
        for plugin in self.pattern_plugins.values():
            plugin.end_file(self.file_path)
            plugin.end()
