\
import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

import pytest


def run_cli(args, cwd=None, env=None, timeout=60):
    """
    Run the CLI as a subprocess: python -m sigscan.cli <args>
    Returns CompletedProcess with stdout/stderr text captured.
    """
    cmd = [sys.executable, "-m", "sigscan.cli"] + list(map(str, args))
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


@pytest.fixture()
def dataset_dir(tmp_path: Path) -> Path:
    """
    Copy the embedded dataset into a temporary directory and return its path.
    """
    src = Path(__file__).parent / "assets" / "dataset"
    dst = tmp_path / "dataset"
    shutil.copytree(src, dst)
    return dst


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    d = tmp_path / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_json(p: Path):
    with p.open("r") as f:
        return json.load(f)


def assert_exit_ok(proc):
    assert proc.returncode == 0, f"Non-zero exit:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"


def assert_file(p: Path):
    assert p.exists(), f"Expected file missing: {p}"
    return p
