\
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, List
from .base import PatternPlugin
from ..core.models import ParsedRecord, Finding


class EndpointsPlugin(PatternPlugin):
    NAME = "endpoints"
    CATEGORY = "endpoints"
    DEFAULT_OUTPUT_STYLES = ["json", "md"]
    # Settings
    WHITELIST = []
    BLACKLIST = []
    REGEXES = [
        re.compile(r"https?://[A-Za-z0-9\.\-:_~/\?#\[\]@!$&'()*+,;=%]+"),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # IPv4
        re.compile(r"(?:(?:GET|POST|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_\-./]+))"),
        re.compile(r"\b[A-Za-z0-9\-_.]+\.(?:com|net|org|io|dev|app|cloud|co|me)\b"),
    ]

    def write_outputs(self, out_dir: Path) -> Dict[str, int]:
        # Write JSON and MD
        data = [f.__dict__ for f in self.findings]
        (out_dir / "endpoints.json").write_text(json.dumps(data, indent=2))

        lines = ["# Endpoints Findings", ""]
        for f in self.findings:
            lines.append(f"- **file**: {f.file_location}  ")
            lines.append(f"  **line**: {f.line_num}  ")
            lines.append(f"  **context**: `{f.context.strip()}`  ")
            if f.secret:
                lines.append(f"  **value**: `{f.secret}`  ")
            lines.append("")
        (out_dir / "endpoints.md").write_text("\n".join(lines))

        return {"findings": len(self.findings), "artifacts": 2}
