\
from pathlib import Path
import json
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_entropy_detection_captures_random_token(dataset_dir: Path, out_dir: Path):
    proc = run_cli(["dir", dataset_dir, "--plugin", "secrets", "--out", out_dir, "--include", "entropy.txt"])
    assert_exit_ok(proc)

    secrets = load_json(assert_file(out_dir / "secrets.json"))
    # Expect our high-entropy token to be present somewhere
    assert any("NH3u4K5V9xQ0tZ2mC7rBb8YpLkSdXaWq" in (i.get("secret") or "") or
               "NH3u4K5V9xQ0tZ2mC7rBb8YpLkSdXaWq" in (i.get("context") or "") for i in secrets)
