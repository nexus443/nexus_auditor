import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional


UNIT_PATTERNS = {
    "python": [
        re.compile(r"^\s*(?:async\s+def|def|class)\s+[A-Za-z_][A-Za-z0-9_]*\b"),
    ],
    "javascript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\("),
        re.compile(r"^\s*(?:export\s+)?class\s+[A-Za-z_$][A-Za-z0-9_$]*\b"),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
    ],
    "typescript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*<*"),
        re.compile(r"^\s*(?:export\s+)?class\s+[A-Za-z_$][A-Za-z0-9_$]*\b"),
        re.compile(r"^\s*(?:export\s+)?(?:interface|type)\s+[A-Za-z_$][A-Za-z0-9_$]*\b"),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
    ],
    "java": [
        re.compile(r"^\s*(?:public|private|protected)?\s*(?:abstract\s+|final\s+)?class\s+[A-Za-z_][A-Za-z0-9_]*\b"),
        re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\]]+\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*\{"),
    ],
    "go": [
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\("),
        re.compile(r"^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s+struct\b"),
    ],
    "rust": [
        re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\("),
        re.compile(r"^\s*(?:pub\s+)?struct\s+[A-Za-z_][A-Za-z0-9_]*\b"),
        re.compile(r"^\s*(?:pub\s+)?impl\b"),
    ],
    "php": [
        re.compile(r"^\s*class\s+[A-Za-z_][A-Za-z0-9_]*\b"),
        re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?function\s+[A-Za-z_][A-Za-z0-9_]*\s*\("),
    ],
}


EXT_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".toml": "config",
    ".env": "config",
}


@dataclass
class Chunk:
    content: str
    tokens_estimated: int
    strategy: str


def estimate_tokens(text: str) -> int:
    """Approximation locale robuste sans dépendance externe."""
    if not text:
        return 0
    return max(1, int(len(text.encode("utf-8", errors="ignore")) / 4))


def detect_language(filepath: str) -> str:
    base = os.path.basename(filepath)
    if base in {"Dockerfile", "docker-compose.yml", "Makefile"}:
        return "config"
    ext = os.path.splitext(base)[1].lower()
    return EXT_LANGUAGE.get(ext, "text")


def resolve_mode_key(mode_config: Dict) -> str:
    label = str(mode_config.get("label", "")).lower()
    if "rapid" in label or "rapide" in label:
        return "rapid"
    if "deep" in label or "profond" in label:
        return "deep"
    if "devsecops" in label:
        return "devsecops"
    return "deep"


def compute_chunk_token_budget(profile_config: Dict, mode_config: Dict) -> int:
    num_ctx = int(profile_config.get("num_ctx", 8192))
    num_predict = int(mode_config.get("num_predict_override") or profile_config.get("num_predict", 1024))
    mode_key = resolve_mode_key(mode_config)

    # Réserve pour prompt système + réponse + marge de sécurité.
    reserve = max(600 + num_predict, int(num_ctx * 0.20))
    available = max(512, num_ctx - reserve)

    mode_factor = {
        "rapid": 0.45,
        "deep": 0.75,
        "devsecops": 0.90,
    }.get(mode_key, 0.75)

    budget = int(available * mode_factor)
    budget = max(256, min(budget, int(num_ctx * 0.92)))
    return budget


def compute_overlap_tokens(chunk_budget_tokens: int, mode_config: Dict) -> int:
    mode_key = resolve_mode_key(mode_config)
    ratio = {
        "rapid": 0.03,
        "deep": 0.08,
        "devsecops": 0.10,
    }.get(mode_key, 0.08)
    minimum = {
        "rapid": 24,
        "deep": 72,
        "devsecops": 96,
    }.get(mode_key, 64)
    overlap = max(minimum, int(chunk_budget_tokens * ratio))
    return min(overlap, max(32, int(chunk_budget_tokens * 0.35)))


def resolve_max_chunks(mode_config: Dict) -> int:
    explicit = mode_config.get("max_chunks_per_file")
    if isinstance(explicit, int) and explicit > 0:
        return explicit
    mode_key = resolve_mode_key(mode_config)
    default_map = {
        "rapid": 1,
        "deep": 3,
        "devsecops": 8,
    }
    return default_map.get(mode_key, 3)


def _tail_for_overlap(text: str, overlap_tokens: int) -> str:
    if overlap_tokens <= 0:
        return ""
    tail_chars = max(0, overlap_tokens * 4)
    if tail_chars == 0:
        return ""
    return text[-tail_chars:]


def _extract_unit_segments(content: str, language: str) -> List[str]:
    patterns = UNIT_PATTERNS.get(language)
    if not patterns:
        return []

    lines = content.splitlines(keepends=True)
    markers = []
    for idx, line in enumerate(lines):
        if any(pattern.match(line) for pattern in patterns):
            markers.append(idx)

    if not markers:
        return []

    segments: List[str] = []
    if markers[0] > 0:
        preamble = "".join(lines[:markers[0]])
        if preamble.strip():
            segments.append(preamble)

    for i, start_idx in enumerate(markers):
        end_idx = markers[i + 1] if i + 1 < len(markers) else len(lines)
        segment = "".join(lines[start_idx:end_idx])
        if segment.strip():
            segments.append(segment)
    return segments


def _is_unit_split_reliable(segments: List[str], content: str, budget_tokens: int) -> bool:
    if len(segments) < 2:
        return False
    tokens = [estimate_tokens(seg) for seg in segments]
    non_trivial = [t for t in tokens if t >= 20]
    if len(non_trivial) < 2:
        return False
    giant_segments = [t for t in tokens if t > int(budget_tokens * 1.6)]
    if len(giant_segments) > max(1, int(len(tokens) * 0.5)):
        return False
    covered = sum(len(seg) for seg in segments)
    coverage_ratio = covered / max(1, len(content))
    return coverage_ratio >= 0.70


def _split_large_block(content: str, budget_tokens: int, overlap_tokens: int, max_chunks: int) -> List[Chunk]:
    if max_chunks <= 0:
        return []

    chunks: List[Chunk] = []
    text_len = len(content)
    if text_len == 0:
        return chunks

    target_chars = max(512, budget_tokens * 4)
    overlap_chars = min(max(0, overlap_tokens * 4), max(0, target_chars // 3))

    start = 0
    while start < text_len and len(chunks) < max_chunks:
        hard_end = min(start + target_chars, text_len)
        if hard_end >= text_len:
            end = text_len
        else:
            look_from = start + int(target_chars * 0.40)
            block_break = content.rfind("\n\n", look_from, hard_end)
            line_break = content.rfind("\n", look_from, hard_end)
            end = block_break + 2 if block_break > start else line_break + 1 if line_break > start else hard_end

        piece = content[start:end].strip()
        if piece:
            chunks.append(Chunk(content=piece, tokens_estimated=estimate_tokens(piece), strategy="blocks"))

        if end >= text_len:
            break

        next_start = end - overlap_chars
        if next_start <= start:
            next_start = end
        start = max(0, next_start)

    return chunks


def _pack_unit_segments(segments: List[str], budget_tokens: int, overlap_tokens: int, max_chunks: int) -> List[Chunk]:
    chunks: List[Chunk] = []
    if max_chunks <= 0:
        return chunks

    current_parts: List[str] = []
    current_tokens = 0
    carry_overlap = ""

    def flush_current():
        nonlocal current_parts, current_tokens, carry_overlap
        if not current_parts:
            return
        text = "\n\n".join(part.rstrip() for part in current_parts if part.strip()).strip()
        if text:
            chunks.append(Chunk(content=text, tokens_estimated=estimate_tokens(text), strategy="units"))
            carry_overlap = _tail_for_overlap(text, overlap_tokens)
        current_parts = []
        current_tokens = 0

    for segment in segments:
        if len(chunks) >= max_chunks:
            break

        part = segment.strip()
        if not part:
            continue

        part_tokens = estimate_tokens(part)
        if part_tokens > int(budget_tokens * 1.2):
            flush_current()
            remaining = max_chunks - len(chunks)
            chunks.extend(_split_large_block(part, budget_tokens, overlap_tokens, remaining))
            if chunks:
                carry_overlap = _tail_for_overlap(chunks[-1].content, overlap_tokens)
            continue

        if current_parts and current_tokens + part_tokens > budget_tokens:
            flush_current()
            if len(chunks) >= max_chunks:
                break
            if carry_overlap:
                combined = f"{carry_overlap}\n{part}"
                if estimate_tokens(combined) <= budget_tokens:
                    current_parts.append(carry_overlap)
                    current_tokens = estimate_tokens(carry_overlap)

        if not current_parts and carry_overlap:
            # Si on ne peut pas inclure l'overlap dans le chunk courant, on le droppe.
            tentative = f"{carry_overlap}\n{part}"
            if estimate_tokens(tentative) <= budget_tokens:
                current_parts.append(carry_overlap)
                current_tokens = estimate_tokens(carry_overlap)
            carry_overlap = ""

        current_parts.append(part)
        current_tokens += part_tokens

    if len(chunks) < max_chunks:
        flush_current()

    return chunks[:max_chunks]


def build_chunk_plan(content: str, filepath: str, profile_config: Dict, mode_config: Dict) -> Dict:
    language = detect_language(filepath)
    token_budget = compute_chunk_token_budget(profile_config, mode_config)
    overlap_tokens = compute_overlap_tokens(token_budget, mode_config)
    max_chunks = resolve_max_chunks(mode_config)

    if not content or not content.strip():
        return {
            "language": language,
            "strategy": "empty",
            "token_budget": token_budget,
            "overlap_tokens": overlap_tokens,
            "max_chunks": max_chunks,
            "chunks": [],
        }

    content_tokens = estimate_tokens(content)
    if content_tokens <= token_budget:
        return {
            "language": language,
            "strategy": "single",
            "token_budget": token_budget,
            "overlap_tokens": overlap_tokens,
            "max_chunks": max_chunks,
            "chunks": [
                {"content": content, "tokens_estimated": content_tokens, "strategy": "single"}
            ],
        }

    segments = _extract_unit_segments(content, language)
    if _is_unit_split_reliable(segments, content, token_budget):
        built = _pack_unit_segments(segments, token_budget, overlap_tokens, max_chunks)
        strategy = "units"
    else:
        built = _split_large_block(content, token_budget, overlap_tokens, max_chunks)
        strategy = "blocks"

    if not built:
        fallback = content[: token_budget * 4]
        built = [Chunk(content=fallback, tokens_estimated=estimate_tokens(fallback), strategy="fallback")]
        strategy = "fallback"

    return {
        "language": language,
        "strategy": strategy,
        "token_budget": token_budget,
        "overlap_tokens": overlap_tokens,
        "max_chunks": max_chunks,
        "chunks": [
            {"content": chunk.content, "tokens_estimated": chunk.tokens_estimated, "strategy": chunk.strategy}
            for chunk in built
        ],
    }

