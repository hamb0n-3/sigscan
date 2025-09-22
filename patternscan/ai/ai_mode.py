\
from __future__ import annotations
from pathlib import Path
import json
import os
import sys
from typing import Any, Dict, List, Optional

AI_PROMPT = """\
You are a security analyst. You are given:
1) An input document (could be notes or a scan summary).
2) A list of extracted potential secrets with context.

Write a concise risk-oriented report that:
- Highlights the most critical items first.
- Groups similar issues together.
- Suggests concrete remediation actions.
- Includes a short 'Evidence' section with file paths and line numbers where relevant.

Keep it to ~600-1000 words.
"""

def _load_text(path: Path) -> str:
    try:
        return path.read_text()
    except Exception as e:
        return ""

def _load_secrets(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []

def _format_context_snippets(secrets: List[Dict[str, Any]], max_items: int = 64) -> str:
    lines = []
    for i, s in enumerate(secrets[:max_items], start=1):
        loc = s.get("file location", "unknown")
        ln = s.get("line_num", "?")
        sec = s.get("secret", "")
        ctx = s.get("context", "").strip()
        cat = s.get("category", "")
        lines.append(f"{i}. [{cat}] {loc}:{ln} :: {sec}\n    {ctx}")
    if len(secrets) > max_items:
        lines.append(f"... {len(secrets) - max_items} more items omitted ...")
    return "\n".join(lines)

def _build_prompt(user_text: str, secrets: List[Dict[str, Any]]) -> str:
    bundle = [
        AI_PROMPT,
        "\n--- INPUT DOCUMENT ---\n",
        user_text,
        "\n--- EXTRACTED CANDIDATES (SECRETS) ---\n",
        _format_context_snippets(secrets),
        "\n--- TASK ---\nDraft the report now.",
    ]
    return "\n".join(bundle)

def run_ai_mode(args) -> int:
    input_file: Path = args.input_file
    output_file: Path = args.output_file
    secrets_file: Path = args.secrets_file
    model_path: Optional[Path] = args.model_path
    max_tokens: int = args.max_tokens
    temperature: float = args.temperature

    user_text = _load_text(input_file)
    secrets = _load_secrets(secrets_file)
    prompt = _build_prompt(user_text, secrets)

    # Try llama_cpp, but degrade gracefully if not available.
    try:
        from llama_cpp import Llama  # type: ignore
    except Exception as e:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            "llama_cpp not available. Install `llama-cpp-python` and provide --model-path to enable AI mode.\n\n"
            "Prompt preview:\n\n" + prompt[:4000]
        )
        print("llama_cpp not available; wrote prompt preview instead.", file=sys.stderr)
        return 0

    if not model_path or not model_path.exists():
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            "Model path not provided or not found. Please pass --model-path pointing to a GGUF model.\n\n"
            "Prompt preview:\n\n" + prompt[:4000]
        )
        print("Missing --model-path; wrote prompt preview instead.", file=sys.stderr)
        return 0

    llm = Llama(model_path=str(model_path), n_ctx=8192, verbose=False)
    res = llm(
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=None,
    )
    text = res["choices"][0]["text"]
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(text.strip())
    return 0
