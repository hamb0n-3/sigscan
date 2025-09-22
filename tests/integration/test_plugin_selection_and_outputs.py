\
from pathlib import Path
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_unknown_plugin_selector_exit_code(dataset_dir: Path, out_dir: Path):
    proc = run_cli(["dir", dataset_dir, "--plugin", "nonexistent", "--out", out_dir])
    # Program should exit non-zero (2)
    assert proc.returncode != 0

def test_outputs_index_and_markdown_exist(dataset_dir: Path, out_dir: Path):
    proc = run_cli(["dir", dataset_dir, "--plugin", "secrets,endpoints,web", "--out", out_dir])
    assert_exit_ok(proc)

    # Index & summary
    index = load_json(assert_file(out_dir / "index.json"))
    assert "plugin" in index[0]
    assert_file(out_dir / "summary.md")

    # Markdown reports per plugin
    assert_file(out_dir / "secrets.md")
    assert_file(out_dir / "endpoints.md")
    assert_file(out_dir / "web.md")
