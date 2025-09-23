from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

from ..core.models import ParsedRecord, Finding
from ..core.utils import shannon_entropy, TOKEN_RE
from .base import PatternPlugin


DEFAULT_ASSIGNMENT_KEYWORDS = [
    r"password",
    r"passphrase",
    r"secret",
    r"secret[_-]?key",
    r"client[_-]?secret",
    r"consumer[_-]?secret",
    r"credential(?:s)?",
    r"connection[_-]?string",
    r"api[_-]?key",
    r"access[_-]?key",
    r"auth[_-]?key",
    r"token",
    r"auth[_-]?token",
    r"access[_-]?token",
    r"refresh[_-]?token",
    r"bearer[_-]?token",
    r"session[_-]?token",
    r"jwt",
    r"private[_-]?key",
    r"ssh[_-]?key",
    r"encryption[_-]?key",
]

ASSIGNMENT_VALUE_PATTERN = r"(?:['\"]?[^\s]{6,}['\"]?)"

BASE_REGEXES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
    re.compile(r"(?i)xox[baprs]-[A-Za-z0-9\-]{10,}"),  # Slack tokens
    re.compile(r"(?i)ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
    re.compile(r"(?i)-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
]


def _build_assignment_regexes() -> List[re.Pattern[str]]:
    """Compile case-insensitive assignment regexes for the configured keywords."""

    return [
        re.compile(
            rf"(?i)[^\n]*(?:{kw})[\w.\-]*\s*(?:[:=]|:=)\s*{ASSIGNMENT_VALUE_PATTERN}"
        )
        for kw in DEFAULT_ASSIGNMENT_KEYWORDS
    ]


DEFAULT_REGEXES = BASE_REGEXES + _build_assignment_regexes()


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
    ASSIGNMENT_KEYWORDS = list(DEFAULT_ASSIGNMENT_KEYWORDS)
    ASSIGNMENT_VALUE = ASSIGNMENT_VALUE_PATTERN
    REGEXES = list(DEFAULT_REGEXES)
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
