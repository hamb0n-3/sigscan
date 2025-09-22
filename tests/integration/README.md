# Integration Test Suite for sigscan

This suite runs the **sigscan** CLI end-to-end as a subprocess and validates outputs.

## How to use

Unzip the archive into your project's `tests/` directory so that you get:

```
tests/
  integration/
    conftest.py
    test_*.py
    assets/
      dataset/
        (sample files)
```

Then run:

```bash
pytest -q
```

The tests will:
- Invoke the CLI via `python -m sigscan.cli ...`
- Scan a curated dataset containing secrets, endpoints, and web artifacts
- Validate JSON/Markdown outputs for each plugin
- Exercise *dir*, *file*, and *ai* modes
- Verify JSON/XML parsers, entropy detection, size limits, and resiliency on binary files
