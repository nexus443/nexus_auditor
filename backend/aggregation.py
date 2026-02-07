import os
import re
from typing import Dict, List, Optional, Tuple


SEVERITY_ORDER = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _sanitize_text(value: str) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _normalize_snippet(snippet: str, max_lines: int = 8, max_chars: int = 320) -> str:
    text = _sanitize_text(snippet)
    if not text:
        return ""
    lines = [line.rstrip() for line in text.splitlines()[:max_lines]]
    compact = "\n".join(lines).strip()
    if len(compact) > max_chars:
        return compact[: max_chars - 3].rstrip() + "..."
    return compact


def _best_severity(a: str, b: str) -> str:
    a_val = SEVERITY_ORDER.get(str(a), 0)
    b_val = SEVERITY_ORDER.get(str(b), 0)
    return a if a_val >= b_val else b


def _extract_symbol(vuln: Dict) -> str:
    direct = _sanitize_text(str(vuln.get("symbol", "")))
    if direct:
        return direct.lower()

    evidence = _sanitize_text(str(vuln.get("evidence", "")))
    snippet = _sanitize_text(str(vuln.get("snippet", "")))
    hay = evidence or snippet
    if not hay:
        return "unknown"

    patterns = [
        r"\b(?:def|class|function|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=",
    ]
    for pattern in patterns:
        match = re.search(pattern, hay)
        if match:
            return match.group(1).lower()

    return "unknown"


def _infer_source_sink(vuln: Dict) -> Tuple[str, str]:
    source = _sanitize_text(str(vuln.get("source", ""))).lower()
    sink = _sanitize_text(str(vuln.get("sink", ""))).lower()
    if source and sink:
        return source, sink

    vuln_type = _sanitize_text(str(vuln.get("type", ""))).upper()
    desc = _sanitize_text(str(vuln.get("description", ""))).lower()
    text = f"{vuln_type} {desc}"

    if "SQL" in vuln_type or "sql" in desc:
        sink = sink or "database_query"
        source = source or "user_input"
    elif "XSS" in vuln_type or "script" in text:
        sink = sink or "html_response"
        source = source or "user_input"
    elif "RCE" in vuln_type or "command" in text:
        sink = sink or "command_execution"
        source = source or "user_input"
    elif "SECRET" in vuln_type or "token" in text or "password" in text:
        sink = sink or "exposed_secret"
        source = source or "code_constant"
    else:
        sink = sink or "unknown_sink"
        source = source or "unknown_source"

    return source, sink


def build_signature(vuln: Dict) -> str:
    vuln_type = _sanitize_text(str(vuln.get("type", "UNKNOWN"))).upper() or "UNKNOWN"
    filepath = _sanitize_text(str(vuln.get("filepath") or vuln.get("file") or "")).lower() or "unknown_file"
    symbol = _extract_symbol(vuln)
    source, sink = _infer_source_sink(vuln)
    return f"{vuln_type}|{filepath}|{symbol}|{sink}|{source}"


def ensure_proof(vuln: Dict) -> Dict:
    line_start = vuln.get("line") if isinstance(vuln.get("line"), int) and vuln.get("line") > 0 else None
    line_end = vuln.get("line_end") if isinstance(vuln.get("line_end"), int) and vuln.get("line_end") > 0 else line_start

    snippet = _sanitize_text(str(vuln.get("snippet", "")))
    evidence = _sanitize_text(str(vuln.get("evidence", "")))
    description = _sanitize_text(str(vuln.get("description", "")))

    proof_snippet = _normalize_snippet(snippet or evidence or description or "Evidence unavailable")
    proof = {
        "path": _sanitize_text(str(vuln.get("filepath") or vuln.get("file") or "unknown_file")),
        "line_start": line_start,
        "line_end": line_end,
        "snippet": proof_snippet,
    }
    vuln["proof"] = proof
    vuln["line"] = line_start
    vuln["line_end"] = line_end
    vuln["snippet"] = proof_snippet
    return vuln


def merge_vulnerability(existing: Dict, incoming: Dict) -> Dict:
    merged = dict(existing)

    sev = _best_severity(str(existing.get("severity", "Unknown")), str(incoming.get("severity", "Unknown")))
    merged["severity"] = sev

    existing_conf = float(existing.get("confidence", 0.0))
    incoming_conf = float(incoming.get("confidence", 0.0))
    merged["confidence"] = round(max(existing_conf, incoming_conf), 2)

    def _line(value):
        return value if isinstance(value, int) and value > 0 else None

    start_candidates = [_line(existing.get("line")), _line(incoming.get("line"))]
    end_candidates = [_line(existing.get("line_end")), _line(incoming.get("line_end"))]

    starts = [v for v in start_candidates if v is not None]
    ends = [v for v in end_candidates if v is not None]
    merged["line"] = min(starts) if starts else None
    merged["line_end"] = max(ends) if ends else merged["line"]

    existing_evidence = _sanitize_text(str(existing.get("evidence", "")))
    incoming_evidence = _sanitize_text(str(incoming.get("evidence", "")))
    if len(incoming_evidence) > len(existing_evidence):
        merged["evidence"] = incoming_evidence

    existing_snippet = _sanitize_text(str(existing.get("snippet", "")))
    incoming_snippet = _sanitize_text(str(incoming.get("snippet", "")))
    if len(incoming_snippet) > len(existing_snippet):
        merged["snippet"] = incoming_snippet

    if _sanitize_text(str(incoming.get("impact", ""))) and incoming.get("impact") != "Non évalué":
        merged["impact"] = incoming.get("impact")

    if incoming.get("needs_manual_review"):
        merged["needs_manual_review"] = True
    if incoming.get("evidence_missing"):
        merged["evidence_missing"] = True

    merged_chunks = set(existing.get("chunk_refs", []) or [])
    merged_chunks.update(incoming.get("chunk_refs", []) or [])
    if isinstance(existing.get("chunk_index"), int):
        merged_chunks.add(existing.get("chunk_index"))
    if isinstance(incoming.get("chunk_index"), int):
        merged_chunks.add(incoming.get("chunk_index"))
    if merged_chunks:
        merged["chunk_refs"] = sorted(merged_chunks)

    merged["merged_from"] = int(existing.get("merged_from", 1)) + int(incoming.get("merged_from", 1))
    return ensure_proof(merged)


def _calibrate_confidence(vuln: Dict, profile_key: str, verify_expected: bool) -> Dict:
    conf = float(vuln.get("confidence", 0.0))
    proof = vuln.get("proof", {}) or {}
    has_snippet = bool(_sanitize_text(str(proof.get("snippet", ""))))
    has_lines = isinstance(proof.get("line_start"), int) and proof.get("line_start") > 0
    needs_manual = bool(vuln.get("needs_manual_review"))
    evidence_missing = bool(vuln.get("evidence_missing"))
    verification_status = _sanitize_text(str(vuln.get("verification_status", ""))).lower()

    if profile_key in {"eco", "balanced"}:
        proof_score = 100.0
        if not has_snippet:
            proof_score -= 35
        if not has_lines:
            proof_score -= 25
        if needs_manual or evidence_missing:
            proof_score -= 20
        proof_score = max(0.0, min(100.0, proof_score))
        conf = (0.7 * conf) + (0.3 * proof_score)
    else:
        # elite/titan: prove-it-or-downgrade
        if verify_expected:
            if verification_status == "confirm":
                conf += 5
            elif verification_status == "uncertain":
                conf -= 15
            elif verification_status in {"reject", "", "unverified"}:
                conf -= 20
            else:
                conf -= 12
        if needs_manual or evidence_missing:
            conf -= 10
        if not has_lines:
            conf -= 8

    vuln["confidence"] = round(max(0.0, min(100.0, conf)), 2)
    return vuln


def aggregate_findings(vulns: List[Dict], profile_key: str, verify_expected: bool = False) -> List[Dict]:
    if not vulns:
        return []

    merged_by_signature: Dict[str, Dict] = {}
    for vuln in vulns:
        candidate = ensure_proof(dict(vuln))
        signature = build_signature(candidate)
        candidate["signature"] = signature

        if signature not in merged_by_signature:
            merged_by_signature[signature] = candidate
        else:
            merged_by_signature[signature] = merge_vulnerability(merged_by_signature[signature], candidate)
            merged_by_signature[signature]["signature"] = signature

    merged = []
    for item in merged_by_signature.values():
        calibrated = _calibrate_confidence(item, profile_key=profile_key, verify_expected=verify_expected)
        merged.append(ensure_proof(calibrated))

    merged.sort(
        key=lambda v: (
            -SEVERITY_ORDER.get(str(v.get("severity", "Unknown")), 0),
            -float(v.get("confidence", 0.0)),
            str(v.get("filepath", "")),
            int(v.get("line") or 0),
        )
    )
    return merged
