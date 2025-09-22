\
import json
from pathlib import Path
from patternscan.cli import main

def test_smoke(tmp_path: Path):
    # Create a small project with a secret-looking value
    sample = tmp_path / "sample.txt"
    sample.write_text("API_KEY=ghp_abcdefghijklmnopqrstuvwxyz123456\nGET /api/v1/users\n")
    out = tmp_path / "out"
    code = main(["dir", str(tmp_path), "--plugin", "secrets,endpoints", "--out", str(out)])
    assert code == 0
    assert (out / "secrets.json").exists()
    data = json.loads((out / "secrets.json").read_text())
    assert any("ghp_" in item["secret"] for item in data)
