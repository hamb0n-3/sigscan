\
from pathlib import Path
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_dir_mode_all_plugins_end_to_end(dataset_dir: Path, out_dir: Path):
    # Run full scan with all plugins
    proc = run_cli(["dir", dataset_dir, "--plugin", "all", "--out", out_dir])
    assert_exit_ok(proc)

    # Core outputs
    assert_file(out_dir / "summary.md")
    index = load_json(assert_file(out_dir / "index.json"))
    plugins = {item["plugin"] for item in index}
    assert {"secrets", "endpoints", "web"} <= plugins

    # Per-plugin outputs
    assert_file(out_dir / "endpoints.json")
    assert_file(out_dir / "web.json")
    secrets_path = assert_file(out_dir / "secrets.json")

    # secrets.json should be valid JSON list with expected keys
    secrets = load_json(secrets_path)
    assert isinstance(secrets, list) and len(secrets) > 0

    # We accept either strict schema or extended schema
    required_any_key = lambda item, key1, key2: (key1 in item) or (key2 in item)
    for item in secrets:
        assert "secret" in item
        assert "context" in item
        assert "line_num" in item
        assert required_any_key(item, "file location", "file_location")
        assert "category" in item

    # Spot check specific detections
    # At least one GitHub token-like or password
    assert any("ghp_" in (i.get("secret") or "") or "password" in (i.get("context") or "") for i in secrets)
