\
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, List
from ..core.models import ParsedRecord, Finding
from ..core.utils import shannon_entropy, TOKEN_RE
from .base import PatternPlugin


class SecretsPlugin(PatternPlugin):
    # Settings up top
    NAME = "secrets"
    CATEGORY = "secrets"
    DEFAULT_OUTPUT_STYLES = ["json", "md"]
    # Whitelist/blacklist/regex configuration
    WHITELIST = [
        "example",
        "placeholder",
        "loremipsum",
    ]
    BLACKLIST = []  # lines containing any of these substrings are ignored
    REGEXES = [
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
        re.compile(r"(?i)secret[_-]?key\s*[:=]\s*([A-Za-z0-9/\+=]{16,})"),
        re.compile(r"(?i)api[_-]?key\s*[:=]\s*([A-Za-z0-9/\+=]{16,})"),
        re.compile(r"(?i)token\s*[:=]\s*([A-Za-z0-9\.\-_]{16,})"),
        re.compile(r"(?i)password\s*[:=]\s*([^ \t]{6,})"),
        re.compile(r"(?i)xox[baprs]-[A-Za-z0-9\-]{10,}"),  # Slack tokens
        re.compile(r"(?i)ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
        re.compile(r"(?i)-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
    ]
    # Entropy settings
    ENTROPY_MIN_LENGTH = 20
    ENTROPY_THRESHOLD = 3.5  # Shannon bits per char (heuristic)
    ENTROPY_MAX_TOKENS_PER_LINE = 10

    def process_record(self, record: ParsedRecord) -> None:
        # First, use standard regex matching behavior from base
        super().process_record(record)

        # Then do entropy-based discovery for anything not caught by regex
        text = record.text

        # Optional: short-circuit if line mentions "test" a lot
        if "test" in text.lower():
            return

        hits = 0
        for m in TOKEN_RE.finditer(text):
            token = m.group(0)
            if len(token) < self.ENTROPY_MIN_LENGTH:
                continue
            if any(w in token for w in self.WHITELIST):
                continue
            H = shannon_entropy(token)
            if H >= self.ENTROPY_THRESHOLD:
                f = Finding(
                    secret=token,
                    context=record.context,
                    line_num=record.line_num,
                    file_location=str(record.file_path),
                    category=self.CATEGORY,
                    meta={"entropy": round(H, 3), "detector": "entropy"},
                )
                self.findings.append(f)
                hits += 1
                if hits >= self.ENTROPY_MAX_TOKENS_PER_LINE:
                    break

    def write_outputs(self, out_dir: Path) -> Dict[str, int]:
        # Always write secrets.json with exact structure:
        # {secret, context (line of the value), line_num, file location, category}
        required = [
            {
                "secret": f.secret,
                "context": f.context,
                "line_num": f.line_num,
                "file location": f.file_location,
                "category": f.category,
            }
            for f in self.findings
        ]
        (out_dir / "secrets.json").write_text(json.dumps(required, indent=2))

        # Also write standard artifacts for convenience
        artifacts = 1
        std_json = out_dir / f"{self.NAME}.json"
        std_json.write_text(json.dumps([f.__dict__ for f in self.findings], indent=2))
        artifacts += 1

        md_lines = [f"# {self.NAME.title()} Findings", ""]
        for f in self.findings:
            md_lines.append(f"- **file**: {f.file_location}  ")
            md_lines.append(f"  **line**: {f.line_num}  ")
            md_lines.append(f"  **secret**: `{f.secret}`  ")
            md_lines.append(f"  **context**: `{f.context.strip()}`  ")
            if f.meta:
                md_lines.append(f"  **meta**: `{json.dumps(f.meta)}`  ")
            md_lines.append("")
        (out_dir / f"{self.NAME}.md").write_text("\n".join(md_lines))
        artifacts += 1

        return {"findings": len(self.findings), "artifacts": artifacts}
