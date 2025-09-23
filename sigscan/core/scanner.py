from __future__ import annotations

import fnmatch
import logging
import threading
import time
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
SLOW_SCAN_THRESHOLD_SECONDS = 2.0


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
        self._progress_bar = None
        self._progress_lock = threading.Lock()
        self._slow_log_threshold = SLOW_SCAN_THRESHOLD_SECONDS

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

        futures = {}
        executor = ThreadPoolExecutor(max_workers=self.workers)
        try:
            self._progress_bar = progress_bar
            futures = {executor.submit(self._scan_file, path): path for path in files}
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
        except KeyboardInterrupt:
            if self.verbose:
                self.logger.info("Scan interrupted by user; shutting down workers")
            raise
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            if progress_bar is not None:
                progress_bar.close()
            self._progress_bar = None
            for plugin in self.pattern_plugins.values():
                plugin.end()

    def _scan_file(self, path: Path) -> None:
        parser = _choose_parser(self.parser_plugins, path)
        parser_name = parser.__class__.__name__
        file_size = self._safe_file_size(path)
        display_path = self._format_display_path(path)
        plugin_count = len(self.pattern_plugins)
        self._update_current_file_display(display_path, parser_name, file_size, plugin_count)

        for plugin in self.pattern_plugins.values():
            plugin.begin_file(path)

        record_count = 0
        start_time = time.perf_counter()
        try:
            for record in parser.parse(path):
                for plugin in self.pattern_plugins.values():
                    plugin.process_record(record)
                record_count += 1
        except Exception as exc:
            if self.verbose:
                self.logger.exception("Failed while scanning %s", path)
            else:
                self.logger.warning("Failed while scanning %s: %s", path, exc)
        finally:
            for plugin in self.pattern_plugins.values():
                plugin.end_file(path)
            duration = time.perf_counter() - start_time
            self._maybe_log_slow_file(
                display_path,
                duration,
                file_size,
                record_count,
                parser_name,
                plugin_count,
            )

    def _format_display_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def _safe_file_size(self, path: Path) -> Optional[int]:
        try:
            return path.stat().st_size
        except OSError as exc:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Unable to stat %s: %s", path, exc)
            return None

    def _update_current_file_display(
        self,
        display_path: str,
        parser_name: str,
        file_size: Optional[int],
        plugin_count: int,
    ) -> None:
        label = display_path
        if len(label) > 60:
            label = f"...{label[-57:]}"
        if self._progress_bar is not None:
            with self._progress_lock:
                self._progress_bar.set_postfix_str(label, refresh=False)
                self._progress_bar.refresh()
        if self.logger.isEnabledFor(logging.DEBUG):
            size_str = f"{file_size:,} bytes" if file_size is not None else "unknown size"
            self.logger.debug(
                "Processing %s (parser=%s, %s, plugins=%d)",
                display_path,
                parser_name,
                size_str,
                plugin_count,
            )
        elif self.verbose:
            self.logger.info("Processing %s", display_path)

    def _maybe_log_slow_file(
        self,
        display_path: str,
        duration: float,
        file_size: Optional[int],
        record_count: int,
        parser_name: str,
        plugin_count: int,
    ) -> None:
        if not self.logger.isEnabledFor(logging.DEBUG):
            return
        if duration < self._slow_log_threshold:
            return

        reasons: List[str] = []
        if file_size is not None and file_size >= 1_000_000:
            reasons.append("large file")
        if record_count >= 5_000:
            reasons.append("many parsed records")
        if plugin_count > 3:
            reasons.append("multiple plugins")
        if not reasons:
            reasons.append("parser workload")

        size_str = f"{file_size:,} bytes" if file_size is not None else "unknown size"
        self.logger.debug(
            "Slow scan for %s took %.2fs (%s). size=%s, records=%d, parser=%s, plugins=%d",
            display_path,
            duration,
            ", ".join(reasons),
            size_str,
            record_count,
            parser_name,
            plugin_count,
        )


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
