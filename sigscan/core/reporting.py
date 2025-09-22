\
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List

from ..patterns.base import PatternPlugin


class Reporter:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir

    def write_all(self, plugins: Dict[str, PatternPlugin]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        index = []
        for name, plugin in plugins.items():
            summary = plugin.write_outputs(self.out_dir)
            index.append({"plugin": name, **summary})
        # write an index.json and a summary.md
        (self.out_dir / "index.json").write_text(json.dumps(index, indent=2))
        lines = ["# Scan Summary", ""]
        for item in index:
            lines.append(f"## {item['plugin']}")
            for k, v in item.items():
                if k == "plugin":
                    continue
                lines.append(f"- {k}: {v}")
            lines.append("")
        (self.out_dir / "summary.md").write_text("\n".join(lines))
