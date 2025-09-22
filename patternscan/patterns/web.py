\
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, List
from .base import PatternPlugin
from ..core.models import ParsedRecord, Finding


class WebPlugin(PatternPlugin):
    NAME = "web"
    CATEGORY = "web"
    DEFAULT_OUTPUT_STYLES = ["json", "md"]
    # Settings
    WHITELIST = []
    BLACKLIST = []
    REGEXES = [
        re.compile(r"<form[^>]+action=[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE),
        re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE),
        re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE),
        re.compile(r"(?i)csrf[_-]?token[^=]*=[\"']?([A-Za-z0-9\-_]{8,})"),
    ]

    def write_outputs(self, out_dir: Path) -> Dict[str, int]:
        data = [f.__dict__ for f in self.findings]
        (out_dir / "web.json").write_text(json.dumps(data, indent=2))

        lines = ["# Web Findings", ""]
        for f in self.findings:
            lines.append(f"- **file**: {f.file_location}  ")
            lines.append(f"  **line**: {f.line_num}  ")
            lines.append(f"  **context**: `{f.context.strip()}`  ")
            if f.secret:
                lines.append(f"  **value**: `{f.secret}`  ")
            lines.append("")
        (out_dir / "web.md").write_text("\n".join(lines))

        return {"findings": len(self.findings), "artifacts": 2}
