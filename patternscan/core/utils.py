\
from __future__ import annotations
import io
import os
import re
import math
import chardet  # type: ignore
from pathlib import Path
from typing import Iterable, Iterator, Optional

BINARY_BYTES = bytes(range(0, 32)) + b"\x7f"

def is_likely_binary(data: bytes, threshold: float = 0.30) -> bool:
    if not data:
        return False
    nontext = sum(1 for b in data if b in BINARY_BYTES and b not in (9, 10, 13))
    return (nontext / len(data)) > threshold

def read_text_safely(path: Path, max_bytes: int = 10_000_000) -> Optional[str]:
    try:
        with path.open("rb") as f:
            head = f.read(min(4096, max_bytes))
            if is_likely_binary(head):
                return None
            rest = f.read(max_bytes - len(head))
            data = head + rest
        enc = chardet.detect(data).get("encoding") or "utf-8"
        return data.decode(enc, errors="replace")
    except Exception:
        return None

TOKEN_RE = re.compile(r"[A-Za-z0-9_\-\/\.\:\?\&\=\+\$]{8,}")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    count = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in count.values())

def iter_lines(text: str) -> Iterator[str]:
    buf = io.StringIO(text)
    for i, line in enumerate(buf, start=1):
        yield line.rstrip("\n")
