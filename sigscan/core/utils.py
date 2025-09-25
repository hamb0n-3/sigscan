\
from __future__ import annotations
import io
import re
import math
import chardet  # type: ignore
from pathlib import Path
from typing import Iterator, Optional

BINARY_BYTES = bytes(range(0, 32)) + b"\x7f"
JAVA_SERIAL_MAGIC = b"\xac\xed"

def is_likely_binary(
    data: bytes, control_threshold: float = 0.30, high_bit_threshold: float = 0.60
) -> bool:
    if not data:
        return False
    total = len(data)
    if 0 in data:
        return True
    if data.startswith(JAVA_SERIAL_MAGIC):
        return True
    control = sum(1 for b in data if b in BINARY_BYTES and b not in (9, 10, 13))
    if (control / total) > control_threshold:
        return True
    high = sum(1 for b in data if b >= 0x80)
    if (high / total) > high_bit_threshold:
        return True
    try:
        data.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return True
    return False

def read_text_safely(path: Path, max_bytes: int = 20_000_000) -> Optional[str]:
    try:
        with path.open("rb") as f:
            head = f.read(min(4096, max_bytes))
            if is_likely_binary(head):
                return None
            rest = f.read(max_bytes - len(head))
            data = head + rest
        if is_likely_binary(data):
            return None
        enc = chardet.detect(data).get("encoding")
        candidates = []
        if enc:
            candidates.append(enc)
        candidates.append('utf-8')
        for candidate in candidates:
            try:
                return data.decode(candidate, errors='strict')
            except (LookupError, UnicodeDecodeError):
                continue
        return None
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
