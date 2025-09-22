\
from pathlib import Path
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_file_mode_secrets_only(dataset_dir: Path, out_dir: Path):
    target = dataset_dir / "single_secrets.txt"
    proc = run_cli(["file", target, "--plugin", "secrets", "--out", out_dir])
    assert_exit_ok(proc)

    secrets = load_json(assert_file(out_dir / "secrets.json"))
    assert len(secrets) > 0
    # Ensure all findings reference the single file scanned
    for item in secrets:
        loc = item.get("file location") or item.get("file_location")
        assert Path(loc).name == target.name
