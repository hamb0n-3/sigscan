\
import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .core.loader import (
    discover_parser_plugins,
    discover_pattern_plugins,
    select_pattern_plugins,
)
from .core.scanner import DirectoryScanner, SingleFileScanner, configure_logging
from .core.reporting import Reporter
from .ai.ai_mode import run_ai_mode


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigscan",
        description="Recursive file parser with pluggable pattern analyzers and AI mode.",
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # dir mode
    d = sub.add_parser("dir", help="Scan a directory recursively.")
    d.add_argument("path", type=Path, help="Directory to scan recursively.")
    d.add_argument("--plugin", default="secrets", help="Comma-delimited pattern plugins to activate (e.g., 'secrets,endpoints') or 'all'.")
    d.add_argument("--out", type=Path, default=Path("./scan_output"), help="Output directory.")
    d.add_argument("--workers", type=int, default=8, help="Number of worker threads for scanning.")
    d.add_argument("--include", default="*", help="Glob(s) to include, comma-separated.")
    d.add_argument("--exclude", default=".git,.venv,node_modules,venv,.tox,.mypy_cache,.pytest_cache,__pycache__", help="Dir names to exclude, comma-separated.")
    d.add_argument("--max-file-size", type=int, default=5_000_000, help="Max file size in bytes to parse (default 5MB).")
    d.add_argument("--no-progress", action="store_true", help="Disable the progress bar during directory scans.")
    d.add_argument("--verbose", action="store_true", help="Enable verbose logging output.")

    # file mode
    f = sub.add_parser("file", help="Scan a single file.")
    f.add_argument("path", type=Path, help="File to scan.")
    f.add_argument("--plugin", default="secrets", help="Comma-delimited pattern plugins to activate or 'all'.")
    f.add_argument("--out", type=Path, default=Path("./scan_output"), help="Output directory.")
    f.add_argument("--verbose", action="store_true", help="Enable verbose logging output.")

    # ai mode
    a = sub.add_parser("ai", help="Run AI summarization/analysis using llama_cpp and secrets.json for context.")
    a.add_argument("--input-file", type=Path, required=True, help="Input text/markdown file to augment with context.")
    a.add_argument("--output-file", type=Path, required=True, help="Where to write the AI-generated report/summary.")
    a.add_argument("--secrets-file", type=Path, default=Path("./scan_output/secrets.json"), help="Path to secrets.json (default: ./scan_output/secrets.json).")
    a.add_argument("--model-path", type=Path, default=None, help="Path to GGUF model file used by llama_cpp.")
    a.add_argument("--max-tokens", type=int, default=768, help="Max new tokens to generate.")
    a.add_argument("--temperature", type=float, default=0.2, help="Sampling temperature.")

    return p


def run_dir(args: argparse.Namespace) -> int:
    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    parser_plugins = discover_parser_plugins()
    pattern_plugins = discover_pattern_plugins()
    activated = select_pattern_plugins(pattern_plugins, args.plugin)

    if not activated:
        print("No pattern plugins selected. Exiting.", file=sys.stderr)
        return 2

    scanner = DirectoryScanner(
        root=args.path,
        parser_plugins=parser_plugins,
        pattern_plugins=activated,
        include_globs=[g.strip() for g in args.include.split(",") if g.strip()],
        exclude_dirs=[e.strip() for e in args.exclude.split(",") if e.strip()],
        max_file_size=args.max_file_size,
        workers=args.workers,
        logger=configure_logging(verbose=args.verbose),
        verbose=args.verbose,
        show_progress=not args.no_progress,
    )
    scanner.scan()

    Reporter(out_dir).write_all(activated)
    return 0


def run_file(args: argparse.Namespace) -> int:
    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    parser_plugins = discover_parser_plugins()
    pattern_plugins = discover_pattern_plugins()
    activated = select_pattern_plugins(pattern_plugins, args.plugin)

    if not activated:
        print("No pattern plugins selected. Exiting.", file=sys.stderr)
        return 2

    scanner = SingleFileScanner(
        file_path=args.path,
        parser_plugins=parser_plugins,
        pattern_plugins=activated,
        logger=configure_logging(verbose=args.verbose),
        verbose=args.verbose,
    )
    scanner.scan()

    Reporter(out_dir).write_all(activated)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.mode == "dir":
        return run_dir(args)
    elif args.mode == "file":
        return run_file(args)
    elif args.mode == "ai":
        return run_ai_mode(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
