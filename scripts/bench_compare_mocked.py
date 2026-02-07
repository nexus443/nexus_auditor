#!/usr/bin/env python3
"""Benchmark comparatif reproductible (mocked LLM) pour Nexus Auditor.

Ce script exécute le pipeline de scan sans dépendance Ollama/FastAPI:
- charge un backend depuis --repo-root
- remplace les dépendances runtime par des stubs
- injecte un LLM mock déterministe
- lance N scans et produit des métriques stables
"""

import argparse
import importlib.util
import json as json_lib
import os
import statistics
import sys
import tempfile
import time
import types
import uuid
from pathlib import Path
from typing import Any, Dict, List


def install_import_stubs() -> None:
    """Installe les stubs minimaux nécessaires à l'import de backend.py."""
    requests_stub = types.ModuleType("requests")

    class _Timeout(Exception):
        pass

    class _ConnectionError(Exception):
        pass

    class _Response:
        def __init__(self, status_code: int = 200, payload: Dict[str, Any] = None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    requests_stub.exceptions = types.SimpleNamespace(Timeout=_Timeout, ConnectionError=_ConnectionError)
    requests_stub.get = lambda *args, **kwargs: _Response(200, {"models": []})
    requests_stub.post = lambda *args, **kwargs: _Response(200, {"response": "[]"})
    sys.modules["requests"] = requests_stub

    fastapi_stub = types.ModuleType("fastapi")
    fastapi_stub.__path__ = []

    class FastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def get(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

    class BackgroundTasks:
        def add_task(self, *args, **kwargs):
            return None

    class HTTPException(Exception):
        def __init__(self, status_code: int = 500, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    fastapi_stub.FastAPI = FastAPI
    fastapi_stub.BackgroundTasks = BackgroundTasks
    fastapi_stub.HTTPException = HTTPException
    sys.modules["fastapi"] = fastapi_stub

    responses_stub = types.ModuleType("fastapi.responses")

    class _FastResponse:
        def __init__(self, *args, **kwargs):
            pass

    responses_stub.FileResponse = _FastResponse
    responses_stub.JSONResponse = _FastResponse
    responses_stub.HTMLResponse = _FastResponse
    sys.modules["fastapi.responses"] = responses_stub

    middleware_stub = types.ModuleType("fastapi.middleware")
    middleware_stub.__path__ = []
    sys.modules["fastapi.middleware"] = middleware_stub

    cors_stub = types.ModuleType("fastapi.middleware.cors")

    class CORSMiddleware:
        pass

    cors_stub.CORSMiddleware = CORSMiddleware
    sys.modules["fastapi.middleware.cors"] = cors_stub

    pydantic_stub = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    def Field(default=None, **kwargs):
        return default

    pydantic_stub.BaseModel = BaseModel
    pydantic_stub.Field = Field
    sys.modules["pydantic"] = pydantic_stub

    git_stub = types.ModuleType("git")

    class Repo:
        @staticmethod
        def clone_from(*args, **kwargs):
            raise RuntimeError("git clone disabled in benchmark harness")

    git_stub.Repo = Repo
    sys.modules["git"] = git_stub


def import_backend_module(repo_root: Path):
    backend_dir = repo_root / "backend"
    backend_path = backend_dir / "backend.py"
    if not backend_path.exists():
        raise FileNotFoundError(f"backend.py introuvable: {backend_path}")

    sys.path.insert(0, str(backend_dir))
    module_name = f"nexus_backend_bench_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, str(backend_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Impossible de charger {backend_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def build_mock_findings(prompt: str, filename: str) -> List[Dict[str, Any]]:
    base_filename = filename.split(" (part")[0]
    findings: List[Dict[str, Any]] = []

    def add_finding(item: Dict[str, Any]):
        findings.append(dict(item))
        duplicate = dict(item)
        duplicate["confidence"] = max(0, min(100, int(item.get("confidence", 70)) - 2))
        findings.append(duplicate)

    if "SELECT * FROM users WHERE username" in prompt:
        add_finding(
            {
                "title": "SQL Injection in user query",
                "type": "SQL Injection",
                "severity": "High",
                "confidence": 92,
                "file": base_filename,
                "line": 8,
                "lines": "8-8",
                "evidence": "query = f\"SELECT * FROM users WHERE username = '{username}'\"",
                "description": "Unsanitized input is concatenated into SQL query.",
                "impact": "Database data disclosure or auth bypass.",
                "recommendation": "Use parameterized queries.",
                "fix": "query = \"SELECT * FROM users WHERE username = ?\"",
            }
        )

    if "os.system(cmd)" in prompt:
        add_finding(
            {
                "title": "Command injection via os.system",
                "type": "Command Injection",
                "severity": "Critical",
                "confidence": 95,
                "file": base_filename,
                "line": 14,
                "lines": "14-14",
                "evidence": "return os.system(cmd)",
                "description": "Untrusted command string reaches shell execution.",
                "impact": "Remote code execution on host.",
                "recommendation": "Use safe command allow-list and subprocess args.",
                "fix": "raise ValueError('command execution disabled')",
            }
        )

    if "hardcodedSecret = \"admin123\"" in prompt:
        add_finding(
            {
                "title": "Hardcoded credential in auth flow",
                "type": "HARDCODED_SECRET",
                "severity": "High",
                "confidence": 88,
                "file": base_filename,
                "line": 2,
                "lines": "2-2",
                "evidence": "const hardcodedSecret = \"admin123\";",
                "description": "Hardcoded password can be extracted and abused.",
                "impact": "Privilege abuse and account takeover.",
                "recommendation": "Use secret manager and hashed credentials.",
                "fix": "const hardcodedSecret = process.env.AUTH_SECRET;",
            }
        )

    if "<div>${name}</div>" in prompt:
        add_finding(
            {
                "title": "Reflected XSS in profile rendering",
                "type": "XSS",
                "severity": "Medium",
                "confidence": 82,
                "file": base_filename,
                "line": 11,
                "lines": "11-11",
                "evidence": "return `<div>${name}</div>`;",
                "description": "Unescaped user content is injected into HTML.",
                "impact": "Session theft and script execution in browser.",
                "recommendation": "Escape HTML or use safe templating APIs.",
                "fix": "return `<div>${escapeHtml(name)}</div>`;",
            }
        )

    return findings


def build_verify_response(prompt: str) -> List[Dict[str, Any]]:
    import re

    match = re.search(r"CANDIDATES:\s*(\[[\s\S]*?\])\s*CODE CHUNK:", prompt)
    if not match:
        return []

    try:
        candidates = json_lib.loads(match.group(1))
    except Exception:
        return []

    verdicts = []
    for item in candidates:
        idx = item.get("idx")
        if not isinstance(idx, int):
            continue
        verdicts.append(
            {
                "idx": idx,
                "verdict": "confirm",
                "confidence_adjustment": 2,
                "reason": "mock verifier confirmation",
            }
        )
    return verdicts


def patch_runtime(module) -> None:
    runtime_dir = Path(tempfile.mkdtemp(prefix="nexus_bench_runtime_"))
    raw_dir = runtime_dir / "raw"
    patches_dir = runtime_dir / "patches"
    raw_dir.mkdir(parents=True, exist_ok=True)
    patches_dir.mkdir(parents=True, exist_ok=True)

    module.HISTORY_FILE = str(runtime_dir / "audit_history.json")
    module.RAW_RESPONSES_DIR = str(raw_dir)
    module.PATCHES_DIR = str(patches_dir)
    module.JSON_LOGS_ENABLED = False
    module.save_to_history = lambda summary: None
    module.ensure_model_available = lambda *args, **kwargs: True
    module.get_ollama_base_url = lambda *args, **kwargs: "http://mock-ollama:11434"

    def muted_log(*args, **kwargs):
        return None

    module.add_log = muted_log

    class FakeResponse:
        def __init__(self, status_code: int, payload: Dict[str, Any]):
            self.status_code = status_code
            self._payload = payload

        def json(self):
            return self._payload

    available_models = sorted(
        {
            str(cfg.get("model"))
            for cfg in getattr(module, "POWER_PROFILES", {}).values()
            if isinstance(cfg, dict) and cfg.get("model")
        }
    )

    def fake_get(url: str, timeout: int = 0, **kwargs):
        if str(url).endswith("/api/tags"):
            return FakeResponse(200, {"models": [{"name": name} for name in available_models]})
        return FakeResponse(200, {})

    def fake_post(url: str, json: Dict[str, Any] = None, timeout: int = 0, **kwargs):
        payload = json or {}
        prompt = str(payload.get("prompt", ""))
        filename = "unknown"
        if "(part" in prompt and "FILE:" in prompt:
            # Prompt templates récents
            for line in prompt.splitlines():
                if line.startswith("FILE:"):
                    filename = line.split("FILE:", 1)[1].strip()
                    break

        if str(url).endswith("/api/pull"):
            return FakeResponse(200, {"status": "success"})

        if str(url).endswith("/api/generate"):
            prompt_lower = prompt.lower()
            if "strict security verifier" in prompt_lower or "candidates:" in prompt_lower:
                data = build_verify_response(prompt)
            else:
                data = build_mock_findings(prompt, filename)
            return FakeResponse(200, {"response": json_lib.dumps(data, ensure_ascii=False)})

        return FakeResponse(200, {})

    module.requests.get = fake_get
    module.requests.post = fake_post


def run_single_scan(module, target: Path, profile: str, mode: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    module.run_scan(str(target), profile, mode, "auto", None)
    elapsed = round(time.perf_counter() - t0, 4)

    state = dict(module.scan_state)
    telemetry = dict(state.get("telemetry", {}))
    stats = dict(state.get("stats", {}))

    findings_total = (
        int(stats.get("critical", 0))
        + int(stats.get("high", 0))
        + int(stats.get("medium", 0))
        + int(stats.get("low", 0))
    )

    return {
        "duration_s": elapsed,
        "stage": state.get("current_stage"),
        "files": int(stats.get("files", 0)),
        "findings_total": findings_total,
        "critical": int(stats.get("critical", 0)),
        "high": int(stats.get("high", 0)),
        "medium": int(stats.get("medium", 0)),
        "low": int(stats.get("low", 0)),
        "tokens_estimated_total": int(telemetry.get("tokens_estimated_total", 0)),
        "chunks_total": int(telemetry.get("chunks_total", 0)),
        "llm_requests": int(telemetry.get("llm_requests", 0)),
        "llm_errors": int(telemetry.get("llm_errors", 0)),
        "failed_analyses": int(state.get("failed_analyses", 0)),
    }


def summarize_runs(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    durations = [row["duration_s"] for row in runs]
    tokens = [row["tokens_estimated_total"] for row in runs]
    findings = [row["findings_total"] for row in runs]
    errors = [row["llm_errors"] + row["failed_analyses"] for row in runs]

    return {
        "runs": len(runs),
        "duration_avg_s": round(statistics.mean(durations), 4),
        "duration_stddev_s": round(statistics.pstdev(durations), 4) if len(durations) > 1 else 0.0,
        "tokens_avg": round(statistics.mean(tokens), 2),
        "tokens_stddev": round(statistics.pstdev(tokens), 2) if len(tokens) > 1 else 0.0,
        "findings_avg": round(statistics.mean(findings), 2),
        "findings_stddev": round(statistics.pstdev(findings), 2) if len(findings) > 1 else 0.0,
        "errors_avg": round(statistics.mean(errors), 2),
        "critical_avg": round(statistics.mean([row["critical"] for row in runs]), 2),
        "high_avg": round(statistics.mean([row["high"] for row in runs]), 2),
        "medium_avg": round(statistics.mean([row["medium"] for row in runs]), 2),
        "low_avg": round(statistics.mean([row["low"] for row in runs]), 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Mocked benchmark for Nexus backend scan pipeline")
    parser.add_argument("--repo-root", required=True, help="Root path containing backend/backend.py")
    parser.add_argument("--target", default="", help="Scan target path (default: <repo-root>/fixtures/mini_repo)")
    parser.add_argument("--label", default="", help="Label for report")
    parser.add_argument("--profile", default="balanced")
    parser.add_argument("--mode", default="deep")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", default="", help="Optional output JSON path")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    target = Path(args.target).resolve() if args.target else (repo_root / "fixtures" / "mini_repo")
    label = args.label or repo_root.name

    install_import_stubs()
    backend_module = import_backend_module(repo_root)
    patch_runtime(backend_module)

    run_rows: List[Dict[str, Any]] = []
    for _ in range(max(1, args.runs)):
        run_rows.append(run_single_scan(backend_module, target, args.profile, args.mode))

    report = {
        "label": label,
        "repo_root": str(repo_root),
        "target": str(target),
        "profile": args.profile,
        "mode": args.mode,
        "runs": run_rows,
        "summary": summarize_runs(run_rows),
    }

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_lib.dumps(report, indent=2), encoding="utf-8")

    print(json_lib.dumps(report, indent=2))


if __name__ == "__main__":
    main()
