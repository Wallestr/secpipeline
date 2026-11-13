from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "knowledge"

TOKEN = re.compile(r"[a-zA-Zа-яА-Я0-9_]{2,}")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN.findall(text)]


def _load_chunks() -> list[dict]:
    chunks: list[dict] = []
    if not DOCS_DIR.exists():
        return chunks
    for path in sorted(DOCS_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        parts = [p.strip() for p in re.split(r"\n##\s+", text) if p.strip()]
        for i, part in enumerate(parts):
            if i == 0 and not text.startswith("##"):
                title = path.stem
                body = part
            else:
                lines = part.splitlines()
                title = lines[0].strip()
                body = "\n".join(lines[1:]).strip()
            chunks.append(
                {
                    "id": f"{path.name}#{i}",
                    "source": path.name,
                    "title": title,
                    "text": body,
                    "tf": Counter(_tokenize(f"{title}\n{body}")),
                }
            )
    return chunks


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    keys = set(a) | set(b)
    dot = sum(a[k] * b[k] for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def answer_question(question: str, top_k: int = 3) -> dict:
    """Очень простой local RAG: tf-cosine по markdown-заметкам, без внешних API."""
    chunks = _load_chunks()
    q = Counter(_tokenize(question))
    ranked = sorted(
        (( _cosine(q, c["tf"]), c) for c in chunks),
        key=lambda x: x[0],
        reverse=True,
    )
    top = [(score, chunk) for score, chunk in ranked[:top_k] if score > 0]
    if not top:
        return {
            "answer": "В локальной базе знаний ничего близкого не нашёл. Добавь заметки в knowledge/.",
            "sources": [],
        }

    bits = []
    sources = []
    for score, chunk in top:
        bits.append(f"### {chunk['title']}\n{chunk['text']}")
        sources.append(f"{chunk['source']} (score={score:.2f})")

    answer = (
        "Собрал куски из локальных заметок (без LLM API):\n\n"
        + "\n\n".join(bits)
    )
    return {"answer": answer, "sources": sources}
