\
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from ..core.models import ParsedRecord, Finding


class PatternPlugin:
    """
    Base class for pattern plugins. Subclasses should set NAME, CATEGORY,
    and define WHITELIST, BLACKLIST, REGEXES at the top. They can also override
    output styles by changing DEFAULT_OUTPUT_STYLES. Settings should live up top.
    """
    NAME: str = "base"
    CATEGORY: str = "general"
    DEFAULT_OUTPUT_STYLES: List[str] = ["json", "md"]
    # Settings (override in subclasses)
    WHITELIST: List[str] = []
    BLACKLIST: List[str] = []
    REGEXES: List[re.Pattern] = []

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    # Lifecycle hooks
    def begin(self) -> None:
        pass

    def end(self) -> None:
        pass

    def begin_file(self, path: Path) -> None:
        self._current_file = path

    def end_file(self, path: Path) -> None:
        pass

    # Streaming API: feed parsed records
    def process_record(self, record: ParsedRecord) -> None:
        text = record.text
        # apply blacklist early
        for pattern in self.BLACKLIST:
            if pattern in text:
                return
        # check regexes
        for rx in self.REGEXES:
            for m in rx.finditer(text):
                val = m.group(0)
                if any(w in val for w in self.WHITELIST):
                    continue
                f = Finding(
                    secret=val if self.CATEGORY == "secrets" else None,
                    context=record.context,
                    line_num=record.line_num,
                    file_location=str(record.file_path),
                    category=self.CATEGORY,
                    meta={"pattern": rx.pattern},
                )
                self.findings.append(f)

    def finalize(self) -> List[Finding]:
        return self.findings

    # Output writers; may be overridden
    def write_outputs(self, out_dir: Path) -> Dict[str, int]:
        # Default: write <name>.json and <name>.md
        names = 0
        out_json = out_dir / f"{self.NAME}.json"
        data = [f.__dict__ for f in self.findings]
        out_json.write_text(json.dumps(data, indent=2))
        names += 1
        out_md = out_dir / f"{self.NAME}.md"
        lines = [f"# {self.NAME.title()} Findings", ""]
        for f in self.findings:
            lines.append(f"- **file**: {f.file_location}  ")
            lines.append(f"  **line**: {f.line_num}  ")
            lines.append(f"  **category**: {f.category}  ")
            if f.secret is not None:
                lines.append(f"  **secret**: `{f.secret}`  ")
            lines.append(f"  **context**: `{f.context.strip()}`  ")
            if f.meta:
                lines.append(f"  **meta**: `{json.dumps(f.meta)}`  ")
            lines.append("")
        out_md.write_text("\n".join(lines))
        names += 1
        return {"findings": len(self.findings), "artifacts": names}
