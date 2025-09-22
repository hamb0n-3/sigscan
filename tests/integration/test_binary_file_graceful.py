\
from pathlib import Path
import os
from .conftest import run_cli, assert_exit_ok

def test_binary_file_does_not_crash(dataset_dir: Path, out_dir: Path):
    # Create a small binary file; scanner should not crash on it
    bin_path = dataset_dir / "binary.bin"
    bin_path.write_bytes(os.urandom(1024))
    proc = run_cli(["dir", dataset_dir, "--plugin", "secrets,endpoints,web", "--out", out_dir])
    assert_exit_ok(proc)
