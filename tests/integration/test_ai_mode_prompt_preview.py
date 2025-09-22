\
from pathlib import Path
from .conftest import run_cli, assert_exit_ok, assert_file

def test_ai_mode_prompt_preview(dataset_dir: Path, out_dir: Path, tmp_path: Path):
    # First run a scan to produce secrets.json
    scan = run_cli(["dir", dataset_dir, "--plugin", "secrets", "--out", out_dir])
    assert_exit_ok(scan)

    # Prepare a small input file
    notes = tmp_path / "notes.md"
    notes.write_text("# Notes\nReview the scan results.\n")

    report = tmp_path / "ai_report.md"
    ai = run_cli(["ai", "--input-file", notes, "--output-file", report, "--secrets-file", out_dir / "secrets.json"])
    assert_exit_ok(ai)

    text = report.read_text()
    # In fallback mode, the tool should include a prompt preview
    assert "Prompt preview" in text
