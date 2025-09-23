from __future__ import annotations

import fnmatch
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterator, List, Optional

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - fallback when tqdm is missing
    tqdm = None  # type: ignore

from ..parsers.base import ParserPlugin
from ..patterns.base import PatternPlugin


DEFAULT_LOGGER_NAME = "sigscan"


def configure_logging(verbose: bool = False, logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """Configure and return a module-level logger.

    This helper ensures the scanner has a configured logger even in script usage
    where ``logging.basicConfig`` was not called. Callers can provide their own
    logger name and set ``verbose`` to elevate the log level.
    """

    logger = logging.getLogger(logger_name)
    level = logging.INFO if verbose else logging.WARNING
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
        )
        logger.addHandler(handler)

    return logger


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
        *,
        logger: Optional[logging.Logger] = None,
        verbose: bool = False,
        show_progress: bool = True,
        progress_desc: str = "Scanning files",
    ) -> None:
        self.root = root
        self.parser_plugins = parser_plugins
        self.pattern_plugins = pattern_plugins
        self.include_globs = include_globs
        self.exclude_dirs = set(exclude_dirs)
        self.max_file_size = max_file_size
        self.workers = workers
        base_logger = logger or logging.getLogger(DEFAULT_LOGGER_NAME)
        self.logger = base_logger.getChild(self.__class__.__name__.lower())
        self.verbose = verbose
        if verbose:
            self.logger.setLevel(logging.INFO)
        self.show_progress = bool(show_progress)
        self.progress_desc = progress_desc

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
                except Exception as exc:
                    if self.verbose:
                        self.logger.warning("Unable to stat %s: %s", p, exc)
                    continue

    def scan(self) -> None:
        files = list(self._iter_files())
        total_files = len(files)

        if self.verbose:
            self.logger.info("Discovered %d file(s) to scan", total_files)

        if not total_files:
            return

        for plugin in self.pattern_plugins.values():
            plugin.begin()

        progress_bar = None
        if self.show_progress and tqdm is not None:
            progress_bar = tqdm(total=total_files, desc=self.progress_desc, unit="file")
        elif self.show_progress and tqdm is None:
            self.logger.info("tqdm is not installed; progress bar disabled")

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self._scan_file, path): path for path in files}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    if self.verbose:
                        self.logger.exception("Error scanning %s", path)
                    else:
                        self.logger.warning("Error scanning %s: %s", path, exc)
                finally:
                    if progress_bar is not None:
                        progress_bar.update(1)

        if progress_bar is not None:
            progress_bar.close()

        for plugin in self.pattern_plugins.values():
            plugin.end()

    def _scan_file(self, path: Path) -> None:
        parser = _choose_parser(self.parser_plugins, path)
        for plugin in self.pattern_plugins.values():
            plugin.begin_file(path)

        try:
            for record in parser.parse(path):
                for plugin in self.pattern_plugins.values():
                    plugin.process_record(record)
        except Exception as exc:
            if self.verbose:
                self.logger.exception("Failed while scanning %s", path)
            else:
                self.logger.warning("Failed while scanning %s: %s", path, exc)
        finally:
            for plugin in self.pattern_plugins.values():
                plugin.end_file(path)


class SingleFileScanner:
    def __init__(
        self,
        file_path: Path,
        parser_plugins: Dict[str, ParserPlugin],
        pattern_plugins: Dict[str, PatternPlugin],
        *,
        logger: Optional[logging.Logger] = None,
        verbose: bool = False,
    ) -> None:
        self.file_path = file_path
        self.parser_plugins = parser_plugins
        self.pattern_plugins = pattern_plugins
        base_logger = logger or logging.getLogger(DEFAULT_LOGGER_NAME)
        self.logger = base_logger.getChild(self.__class__.__name__.lower())
        self.verbose = verbose
        if verbose:
            self.logger.setLevel(logging.INFO)

    def scan(self) -> None:
        parser = _choose_parser(self.parser_plugins, self.file_path)
        for plugin in self.pattern_plugins.values():
            plugin.begin()

        for plugin in self.pattern_plugins.values():
            plugin.begin_file(self.file_path)

        try:
            for rec in parser.parse(self.file_path):
                for plugin in self.pattern_plugins.values():
                    plugin.process_record(rec)
        except Exception as exc:
            if self.verbose:
                self.logger.exception("Failed while scanning %s", self.file_path)
            else:
                self.logger.warning("Failed while scanning %s: %s", self.file_path, exc)
        finally:
            for plugin in self.pattern_plugins.values():
                plugin.end_file(self.file_path)
                plugin.end()
