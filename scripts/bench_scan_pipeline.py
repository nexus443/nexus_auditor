#!/usr/bin/env python3
"""Mini benchmark reproductible pour la pipeline Nexus Auditor.

Usage offline (sans backend/Ollama):
  python3 scripts/bench_scan_pipeline.py --offline

Usage online (backend lancé):
  python3 scripts/bench_scan_pipeline.py --runs 3 --profile eco --mode rapid
"""

import argparse
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_KEYS = ("critical", "high", "medium", "low")


def http_json(base_url: str, path: str, method: str = "GET", payload: Dict[str, Any] = None, timeout: int = 30) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    body = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(url=url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)


def local_repo_stats(target: Path) -> Dict[str, Any]:
    file_count = 0
    total_bytes = 0
    for root, _, files in os.walk(target):
        for name in files:
            file_count += 1
            total_bytes += (Path(root) / name).stat().st_size
    return {"path": str(target), "files": file_count, "bytes": total_bytes}


def run_single_scan(
    api_url: str,
    target: str,
    profile: str,
    mode: str,
    poll_interval: float,
    timeout_s: int
) -> Dict[str, Any]:
    start_payload = {
        "target": target,
        "profile": profile,
        "mode": mode,
        "ollama_mode": "auto",
        "ollama_url": None,
    }

    start_resp = http_json(api_url, "/scan/start", method="POST", payload=start_payload, timeout=15)
    if not start_resp.get("success"):
        raise RuntimeError(f"scan/start rejected: {start_resp}")

    t0 = time.time()
    deadline = t0 + timeout_s
    last_status = {}

    while time.time() < deadline:
        last_status = http_json(api_url, "/scan/status", method="GET", timeout=15)
        is_scanning = bool(last_status.get("is_scanning", False))
        progress = int(last_status.get("progress", 0))
        stage = str(last_status.get("current_stage", "")).lower()

        if not is_scanning and (progress >= 100 or stage in {"completed", "failed", "stopped"}):
            break

        time.sleep(poll_interval)
    else:
        raise TimeoutError(f"scan/status timeout after {timeout_s}s")

    duration_s = round(time.time() - t0, 2)
    stats = last_status.get("stats", {})
    telemetry = last_status.get("telemetry", {})
    llm_latency = telemetry.get("llm_latency_ms", {})

    return {
        "duration_s": duration_s,
        "stage": last_status.get("current_stage"),
        "progress": last_status.get("progress"),
        "findings_total": sum(int(stats.get(k, 0)) for k in SEVERITY_KEYS),
        "findings": {k: int(stats.get(k, 0)) for k in SEVERITY_KEYS},
        "files_scheduled": int(telemetry.get("files_scheduled", 0)),
        "files_processed": int(telemetry.get("files_processed", 0)),
        "chunks_total": int(telemetry.get("chunks_total", 0)),
        "chunks_processed": int(telemetry.get("chunks_processed", 0)),
        "tokens_estimated_total": int(telemetry.get("tokens_estimated_total", 0)),
        "llm_requests": int(telemetry.get("llm_requests", 0)),
        "llm_errors": int(telemetry.get("llm_errors", 0)),
        "llm_latency_avg_ms": float(llm_latency.get("avg", 0.0)),
        "llm_latency_max_ms": float(llm_latency.get("max", 0.0)),
        "stage_timings_ms": telemetry.get("stage_timings_ms", {}),
    }


def aggregate_runs(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    durations = [r["duration_s"] for r in runs]
    tokens = [r["tokens_estimated_total"] for r in runs]
    llm_requests = [r["llm_requests"] for r in runs]
    llm_errors = [r["llm_errors"] for r in runs]

    findings_by_sev = {k: [r["findings"][k] for r in runs] for k in SEVERITY_KEYS}

    return {
        "runs": len(runs),
        "duration_avg_s": round(statistics.mean(durations), 2) if durations else 0,
        "duration_stdev_s": round(statistics.pstdev(durations), 2) if len(durations) > 1 else 0,
        "tokens_avg": round(statistics.mean(tokens), 2) if tokens else 0,
        "llm_requests_avg": round(statistics.mean(llm_requests), 2) if llm_requests else 0,
        "llm_errors_avg": round(statistics.mean(llm_errors), 2) if llm_errors else 0,
        "findings_avg": {k: round(statistics.mean(v), 2) if v else 0 for k, v in findings_by_sev.items()},
    }


def print_runs_table(runs: List[Dict[str, Any]]):
    header = "run | duration_s | files | chunks | tokens_est | llm_req | llm_err | crit/high/med/low"
    print(header)
    print("-" * len(header))
    for idx, run in enumerate(runs, start=1):
        f = run["findings"]
        sev = f"{f['critical']}/{f['high']}/{f['medium']}/{f['low']}"
        print(
            f"{idx:>3} | "
            f"{run['duration_s']:>10} | "
            f"{run['files_processed']:>5} | "
            f"{run['chunks_processed']:>6} | "
            f"{run['tokens_estimated_total']:>10} | "
            f"{run['llm_requests']:>7} | "
            f"{run['llm_errors']:>7} | "
            f"{sev}"
        )


def main():
    root_dir = Path(__file__).resolve().parents[1]
    default_target = root_dir / "fixtures" / "mini_repo"

    parser = argparse.ArgumentParser(description="Nexus Auditor scan pipeline baseline benchmark")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--target", default=str(default_target), help="Scan target (path or git URL)")
    parser.add_argument("--profile", default="eco", choices=["eco", "balanced", "elite", "titan"])
    parser.add_argument("--mode", default="rapid", choices=["rapid", "deep", "devsecops"])
    parser.add_argument("--runs", type=int, default=3, help="Number of benchmark runs")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--timeout", type=int, default=900, help="Per-run timeout in seconds")
    parser.add_argument("--output", default="", help="Optional JSON output file path")
    parser.add_argument("--offline", action="store_true", help="Only print local fixture stats")
    args = parser.parse_args()

    local_stats = local_repo_stats(Path(args.target))
    print(f"[bench] target={local_stats['path']} files={local_stats['files']} bytes={local_stats['bytes']}")

    if args.offline:
        print("[bench] offline mode enabled, no API call performed.")
        return

    results = []
    for run_idx in range(1, args.runs + 1):
        print(f"[bench] run {run_idx}/{args.runs} ...")
        result = run_single_scan(
            api_url=args.api_url,
            target=args.target,
            profile=args.profile,
            mode=args.mode,
            poll_interval=args.poll_interval,
            timeout_s=args.timeout,
        )
        results.append(result)
        print(
            f"[bench] done run {run_idx}: "
            f"duration={result['duration_s']}s "
            f"findings={result['findings_total']} "
            f"llm_req={result['llm_requests']} "
            f"tokens~={result['tokens_estimated_total']}"
        )

    aggregate = aggregate_runs(results)
    print()
    print_runs_table(results)
    print()
    print("[bench] aggregate:")
    print(json.dumps(aggregate, indent=2))

    if args.output:
        payload = {
            "generated_at": datetime.now().isoformat(),
            "api_url": args.api_url,
            "target": args.target,
            "profile": args.profile,
            "mode": args.mode,
            "runs": results,
            "aggregate": aggregate,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[bench] results written to {output_path}")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        print(f"[bench] backend unreachable: {exc}")
        raise SystemExit(2)
    except Exception as exc:
        print(f"[bench] error: {exc}")
        raise SystemExit(1)
