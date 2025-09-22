\
from pathlib import Path
import os
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_max_file_size_skips_large_file(dataset_dir: Path, out_dir: Path, tmp_path: Path):
    # Create a large file > 5MB with a would-be secret string
    large = dataset_dir / "large.txt"
    with large.open("wb") as f:
        f.write(b"password=ShouldBeSkippedDueToSize\n")
        f.write(os.urandom(6_000_000))

    proc = run_cli(["dir", dataset_dir, "--plugin", "secrets", "--out", out_dir])
    assert_exit_ok(proc)
    secrets = load_json(assert_file(out_dir / "secrets.json"))
    assert not any("ShouldBeSkippedDueToSize" in (i.get("secret") or "") or
                   "ShouldBeSkippedDueToSize" in (i.get("context") or "") for i in secrets)

def test_include_globs_limit(dataset_dir: Path, out_dir: Path):
    # Include only JSON and XML files
    proc = run_cli(["dir", dataset_dir, "--plugin", "endpoints", "--out", out_dir, "--include", "*.json,*.xml"])
    assert_exit_ok(proc)
    # endpoints.json should be present
    data = load_json(assert_file(out_dir / "endpoints.json"))
    assert len(data) >= 1
