\
from pathlib import Path
from .conftest import run_cli, load_json, assert_exit_ok, assert_file

def test_json_and_xml_parsers(dataset_dir: Path, out_dir: Path):
    # Limit to json and xml to focus on parser behavior
    proc = run_cli(["dir", dataset_dir, "--plugin", "secrets,endpoints", "--out", out_dir, "--include", "*.json,*.xml"])
    assert_exit_ok(proc)

    secrets = load_json(assert_file(out_dir / "secrets.json"))
    assert any("XmlPass" in (i.get("secret") or "") or "XmlPass" in (i.get("context") or "") for i in secrets)
    assert any("Pa$$w0rd!" in (i.get("secret") or "") for i in secrets)

    endpoints = load_json(assert_file(out_dir / "endpoints.json"))
    assert any("xml.example.org" in (i.get("context") or "") for i in endpoints)
    assert any("service.example.com" in (i.get("context") or "") for i in endpoints)
