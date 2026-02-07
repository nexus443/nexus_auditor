import os
import sys
import json
import re
import math
import requests
import shutil
import tempfile
import time
import uuid
import difflib
import signal
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from git import Repo

try:
    from .chunker import build_chunk_plan, compute_chunk_token_budget, resolve_max_chunks
except ImportError:
    from chunker import build_chunk_plan, compute_chunk_token_budget, resolve_max_chunks

try:
    from .llm_budget_controller import LLMBudgetController
except ImportError:
    from llm_budget_controller import LLMBudgetController

try:
    from .scan_mode_controller import ScanModeController
except ImportError:
    from scan_mode_controller import ScanModeController

try:
    from .aggregation import aggregate_findings, ensure_proof
except ImportError:
    from aggregation import aggregate_findings, ensure_proof

# ==========================================
# ⚙️ NEXUS AUDITOR V3.0 STABLE
# ==========================================
# Architecture: V2.2 base + améliorations contrôlées
# Principe: Stabilité > Sophistication
# ==========================================

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_BASE_URL = OLLAMA_URL.replace("/api/generate", "")  # Pour les autres endpoints
HISTORY_FILE = "audit_history.json"
RAW_RESPONSES_DIR = "./audit_logs/raw_responses"
PATCHES_DIR = "./audit_logs/patches"

os.makedirs(RAW_RESPONSES_DIR, exist_ok=True)
os.makedirs(PATCHES_DIR, exist_ok=True)

JSON_LOGS_ENABLED = os.getenv("NEXUS_JSON_LOGS", "1").strip().lower() not in {"0", "false", "no", "off"}

PIPELINE_STAGES = ("normalize", "index", "analyze", "correlate", "report")


def _pipeline_stage_index(stage_name: str) -> int:
    try:
        return PIPELINE_STAGES.index(stage_name) + 1
    except ValueError:
        return 0


def init_stage_report(current_stage: str = "idle") -> dict:
    stage_status = {stage: "pending" for stage in PIPELINE_STAGES}
    completed: List[str] = []
    current_index = _pipeline_stage_index(current_stage)

    if current_index:
        for stage in PIPELINE_STAGES[: current_index - 1]:
            stage_status[stage] = "completed"
            completed.append(stage)
        stage_status[current_stage] = "active"

    return {
        "sequence": list(PIPELINE_STAGES),
        "current": current_stage,
        "current_index": current_index,
        "completed": completed,
        "stage_status": stage_status,
        "terminal_state": None,
        "updated_at": datetime.now().isoformat(),
    }


def mark_stage_terminal_state(terminal_state: str):
    report = scan_state.setdefault("stage_report", init_stage_report(scan_state.get("current_stage", "idle")))
    report["terminal_state"] = terminal_state
    report["current"] = terminal_state
    if terminal_state == "completed":
        report["stage_status"] = {stage: "completed" for stage in PIPELINE_STAGES}
        report["completed"] = list(PIPELINE_STAGES)
        report["current_index"] = len(PIPELINE_STAGES)
    report["updated_at"] = datetime.now().isoformat()


def init_scan_telemetry() -> dict:
    """Structure de télémétrie minimale (baseline instrumentation)."""
    return {
        "stage_timings_ms": {},
        "llm_requests": 0,
        "llm_success": 0,
        "llm_errors": 0,
        "llm_latency_ms": {"count": 0, "avg": 0.0, "min": None, "max": 0.0, "last": 0.0},
        "files_discovered": 0,
        "files_scheduled": 0,
        "files_processed": 0,
        "chunks_total": 0,
        "chunks_processed": 0,
        "tokens_estimated_total": 0,
        "bytes_discovered": 0,
        "bytes_scheduled": 0,
        "chunks_by_file": {},
        "tokens_estimated_by_file": {},
    }


def estimate_tokens_from_text(text: str) -> int:
    """
    Estimation légère de tokens:
    - on utilise la taille UTF-8 / 4 pour obtenir un ordre de grandeur stable.
    """
    if not text:
        return 0
    return max(1, int(len(text.encode("utf-8", errors="ignore")) / 4))


def redact_sensitive_text(value: str) -> str:
    """Masque les secrets évidents avant logs structurés."""
    if not isinstance(value, str):
        return value

    redacted = value

    # Credentials in URLs: scheme://user:pass@host -> scheme://***:***@host
    redacted = re.sub(
        r'([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/\s:@]+):([^@\s/]+)@',
        r'\1***:***@',
        redacted
    )

    # Query params secrets: ?token=...&api_key=...
    redacted = re.sub(
        r'([?&](?:token|api[_-]?key|key|password|secret)=)([^&\s]+)',
        r'\1***',
        redacted,
        flags=re.IGNORECASE
    )

    # Bearer tokens
    redacted = re.sub(
        r'(?i)\b(bearer\s+)[A-Za-z0-9._\-~+/=]+',
        r'\1***',
        redacted
    )

    # Generic key=value forms
    redacted = re.sub(
        r'(?i)\b(api[_-]?key|token|password|passwd|secret)\s*[:=]\s*([^\s,;]+)',
        r'\1=***',
        redacted
    )

    # OpenAI-like keys
    redacted = re.sub(r'\bsk-[A-Za-z0-9]{10,}\b', '***', redacted)

    return redacted


def sanitize_for_log(value: Any) -> Any:
    """Sanitize recursively log payload values."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, dict):
        return {str(k): sanitize_for_log(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_for_log(v) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize_for_log(v) for v in value)
    return value


def start_scan_stage(stage_name: str) -> float:
    scan_state["current_stage"] = stage_name
    report = scan_state.setdefault("stage_report", init_stage_report(stage_name))
    stage_status = report.setdefault("stage_status", {stage: "pending" for stage in PIPELINE_STAGES})
    for stage in PIPELINE_STAGES:
        stage_status.setdefault(stage, "pending")
    if stage_name in stage_status:
        stage_status[stage_name] = "active"
    report["current"] = stage_name
    report["current_index"] = _pipeline_stage_index(stage_name)
    report["terminal_state"] = None
    report["updated_at"] = datetime.now().isoformat()
    add_log(f"▶ Stage {stage_name}", "info", stage=stage_name, event="stage_start")
    return time.time()


def end_scan_stage(stage_name: str, started_at: Optional[float]):
    if started_at is None:
        return
    elapsed_ms = round((time.time() - started_at) * 1000, 2)
    telemetry = scan_state.setdefault("telemetry", init_scan_telemetry())
    stage_timings = telemetry.setdefault("stage_timings_ms", {})
    stage_timings[stage_name] = round(stage_timings.get(stage_name, 0.0) + elapsed_ms, 2)
    report = scan_state.setdefault("stage_report", init_stage_report(scan_state.get("current_stage", "idle")))
    stage_status = report.setdefault("stage_status", {stage: "pending" for stage in PIPELINE_STAGES})
    for stage in PIPELINE_STAGES:
        stage_status.setdefault(stage, "pending")
    if stage_name in stage_status:
        stage_status[stage_name] = "completed"
    completed = report.setdefault("completed", [])
    if stage_name in PIPELINE_STAGES and stage_name not in completed:
        completed.append(stage_name)
        completed.sort(key=lambda item: PIPELINE_STAGES.index(item))
    report["updated_at"] = datetime.now().isoformat()
    add_log(
        f"✅ Stage {stage_name} terminé ({elapsed_ms:.0f}ms)",
        "info",
        stage=stage_name,
        event="stage_end",
        duration_ms=elapsed_ms,
    )


def switch_scan_stage(current_stage: Optional[str], started_at: Optional[float], next_stage: str) -> Tuple[str, float]:
    if current_stage:
        end_scan_stage(current_stage, started_at)
    return next_stage, start_scan_stage(next_stage)


def record_llm_call_metrics(
    filename: str,
    latency_ms: float,
    success: bool,
    attempt: int,
    chunk_index: Optional[int] = None,
    chunk_total: Optional[int] = None,
    status_code: Optional[int] = None,
    error: Optional[str] = None
):
    telemetry = scan_state.setdefault("telemetry", init_scan_telemetry())

    telemetry["llm_requests"] += 1
    if success:
        telemetry["llm_success"] += 1
    else:
        telemetry["llm_errors"] += 1

    latency = telemetry.setdefault("llm_latency_ms", {"count": 0, "avg": 0.0, "min": None, "max": 0.0, "last": 0.0})
    latency["count"] += 1
    latency["last"] = round(latency_ms, 2)
    latency["max"] = round(max(latency.get("max", 0.0), latency_ms), 2)
    latency["min"] = round(latency_ms, 2) if latency.get("min") is None else round(min(latency["min"], latency_ms), 2)
    prev_avg = float(latency.get("avg", 0.0))
    latency["avg"] = round(prev_avg + ((latency_ms - prev_avg) / max(1, latency["count"])), 2)

    add_log(
        f"⏱️ LLM {filename}: {latency_ms:.0f}ms",
        "info" if success else "warning",
        stage="analyze",
        event="llm_request",
        filename=filename,
        latency_ms=round(latency_ms, 2),
        attempt=attempt,
        chunk_index=chunk_index,
        chunk_total=chunk_total,
        status_code=status_code,
        success=success,
        error=error,
    )

# ==========================================
# 🔗 OLLAMA CONNECTION MANAGEMENT
# ==========================================

def normalize_ollama_url(url: str) -> str:
    """Normalise une URL Ollama (trim, ajoute http://, enlève / final)"""
    url = url.strip()
    if not url:
        raise ValueError("URL Ollama vide")
    
    # Ajouter http:// si absent
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Enlever / final
    url = url.rstrip('/')
    
    return url

def get_ollama_base_url(scan_request: Optional['ScanRequest'] = None, ollama_mode: str = "auto", ollama_url: Optional[str] = None) -> str:
    """Retourne l'URL de base Ollama selon le mode (auto ou remote)"""
    # Si scan_request fourni, utiliser ses paramètres
    if scan_request:
        ollama_mode = scan_request.ollama_mode
        ollama_url = scan_request.ollama_url
    
    if ollama_mode == "remote":
        if not ollama_url:
            raise ValueError("Mode remote sélectionné mais URL Ollama manquante")
        return normalize_ollama_url(ollama_url)
    else:
        # Mode auto: utiliser OLLAMA_BASE_URL existant
        return OLLAMA_BASE_URL



# ==========================================
# 🤖 GESTION AUTOMATIQUE DES MODÈLES
# ==========================================

def get_installed_models(ollama_base_url: str = None) -> set:
    """Récupère la liste des modèles installés dans Ollama"""
    try:
        # V3.4: Reduced timeout from 10s to 3s for faster feedback in Docker
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        if response.status_code == 200:
            data = response.json()
            models = {m.get("name", "") for m in data.get("models", [])}
            return models
    except Exception as e:
        print(f"[Ollama] ⚠️ Impossible de lister les modèles: {e}")
    return set()

def is_model_installed(model_name: str, ollama_base_url: str = None) -> bool:
    """Vérifie si un modèle spécifique est installé"""
    installed = get_installed_models(ollama_base_url)
    # Vérifier nom exact ou sans tag
    return model_name in installed or model_name.split(":")[0] in {m.split(":")[0] for m in installed}

def pull_model(model_name: str, ollama_base_url: str = None) -> bool:
    """Télécharge un modèle Ollama (peut prendre du temps)"""
    base_url = ollama_base_url or OLLAMA_BASE_URL
    print(f"[Ollama] 📥 Téléchargement du modèle {model_name}...")
    add_log(f"📥 Téléchargement du modèle {model_name} en cours...", "info")  # V3.4: Log visible
    try:
        response = requests.post(
            f"{base_url}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=3600  # 1 heure max pour les gros modèles
        )
        if response.status_code == 200:
            print(f"[Ollama] ✅ Modèle {model_name} installé avec succès")
            add_log(f"✅ Modèle {model_name} installé", "success")  # V3.4: Log visible
            return True
        else:
            print(f"[Ollama] ❌ Erreur téléchargement: {response.status_code}")
            add_log(f"❌ Erreur téléchargement modèle: HTTP {response.status_code}", "error")  # V3.4: Log visible
            return False
    except Exception as e:
        print(f"[Ollama] ❌ Erreur: {e}")
        add_log(f"❌ Erreur téléchargement: {str(e)[:100]}", "error")  # V3.4: Log visible
        return False

def ensure_model_available(model_name: str, ollama_base_url: str = None) -> bool:
    """Vérifie et installe le modèle si nécessaire. Retourne True si disponible."""
    add_log(f"🔍 Vérification disponibilité du modèle {model_name}...", "info")  # V3.4: Log immédiat
    if is_model_installed(model_name, ollama_base_url):
        print(f"[Ollama] ✅ Modèle {model_name} déjà installé")
        add_log(f"✅ Modèle {model_name} déjà disponible", "success")  # V3.4: Log visible
        return True
    
    print(f"[Ollama] ⚠️ Modèle {model_name} non trouvé, installation en cours...")
    add_log(f"⚠️ Modèle {model_name} non trouvé, installation...", "warning")  # V3.4: Log visible
    return pull_model(model_name, ollama_base_url)



# ==========================================
# 🧠 PROMPT IA STRICT (ANTI-HALLUCINATION)
# ==========================================
# Ce prompt est COURT et STRICT - NE PAS ALOURDIR
# NOTE: Les accolades JSON sont doublées {{}} pour éviter les conflits avec .format()

CORE_PROMPT = """You are a professional security code auditor.

Your task is to identify REAL, CONFIRMED security vulnerabilities
based ONLY on the provided source code.

Rules:
- Do NOT invent vulnerabilities
- Do NOT speculate
- Do NOT assume missing context
- If evidence is insufficient, return no finding

For each vulnerability:
- Provide the exact code snippet
- Provide line numbers
- Explain why it is vulnerable
- Describe a realistic exploitation scenario

Return ONLY valid JSON using this schema:
[
  {{
    "title": "string",
    "type": "string",
    "severity": "Critical|High|Medium|Low",
    "confidence": 0-100,
    "file": "string",
    "lines": "start-end",
    "evidence": "exact code",
    "impact": "realistic impact",
    "recommendation": "specific mitigation"
  }}
]

If no confirmed vulnerability exists, return []

CODE FILE ({filename}):
```
{content}
```
"""

VERIFY_PROMPT = """You are a strict security verifier.

Validate each candidate finding against the provided code chunk.
Rules:
- Return JSON only.
- verdict must be one of: confirm, uncertain, reject.
- Reject when evidence does not exist in the code.
- Be conservative: uncertain if proof is partial.

Return schema:
[
  {
    "idx": 0,
    "verdict": "confirm|uncertain|reject",
    "confidence_adjustment": -30..10,
    "reason": "short reason"
  }
]

FILE: {filename}
CANDIDATES:
{candidates_json}

CODE CHUNK:
```
{content}
```
"""

# ==========================================
# ⚡ PROFILS DE PUISSANCE (INFRASTRUCTURE)
# ==========================================
# V3.1: Calibrage Strict Hardware (LOCKED for Stability)
POWER_PROFILES = {
    "eco": {
        "label": "🍃 Eco (Mac M1 / CPU)",
        "description": "Stabilité maximale (Low Ram)",
        "model": "qwen2.5-coder:7b",
        "num_ctx": 8192,
        "num_predict": 1024,
        "chunk_size": 12000, # Approx 4000 tokens (safe for 8k ctx)
        "timeout": 60,
        "parallel_files": 1,
    },
    "balanced": {
        "label": "⚖️ Balanced (RTX 3060)",
        "description": "Précision stable (Mid Ram)",
        "model": "qwen2.5-coder:14b",
        "num_ctx": 16384,
        "num_predict": 2048,
        "chunk_size": 24000, # Approx 8000 tokens (safe for 16k ctx)
        "timeout": 90,
        "parallel_files": 1,
    },
    "elite": {
        "label": "🚀 Elite (RTX 3090/4090)",
        "description": "Haute fidélité",
        "model": "qwen2.5-coder:32b",
        "num_ctx": 32768,
        "num_predict": 4096,
        "chunk_size": 40000,
        "timeout": 180,
        "parallel_files": 2,
    },
    "titan": {
        "label": "🔥 Titan (RTX 5090 / Enterprise)",
        "description": "Audit expert entreprise",
        "model": "qwen2.5-coder:32b",
        "num_ctx": 65536,
        "num_predict": 8192,
        "chunk_size": 80000,
        "timeout": 300,
        "parallel_files": 4,
    }
}

# ==========================================
# 🎯 MODES DE SCAN (BUDGET PROFILAGE)
# ==========================================
# V3.1: Profondeur d'analyse et Filtrage
SCAN_MODES = {
    "rapid": {
        "label": "Scan Rapide",
        "description": "Critique uniquement",
        "max_files": 30,
        "max_time_per_file": 20,
        "max_vulns_per_file": 3,
        "min_severity": "High",
        "min_severity_order": 3,
        "min_confidence": 50,  # Strict
        "num_predict_override": 256,
        "file_extensions": ('.py', '.js', '.ts', '.php', '.java', '.go'),
        "enable_prudent_detection": False,
        "description_long": "Filtrage sévère (Confiance 50%+, Sévérité High+)"
    },
    "deep": {
        "label": "Scan Profond",
        "description": "Audit standard entreprise",
        "max_files": 100,
        "max_time_per_file": 60,
        "max_vulns_per_file": 10,
        "min_severity": "Medium",
        "min_severity_order": 2,
        "min_confidence": 35,  # V3.1: Compromis idéal
        "num_predict_override": None,
        "file_extensions": ('.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', 
                           '.c', '.cpp', '.rs', '.go', '.sql'),
        "enable_prudent_detection": True,  # 35-50%
        "description_long": "Audit équilibré (Confiance 35%+, Sévérité Medium+)"
    },
    "devsecops": {
        "label": "DevSecOps",
        "description": "Exhaustivité Maximale",
        "max_files": None,
        "max_time_per_file": 120,
        "max_vulns_per_file": 20,
        "min_severity": "Low",
        "min_severity_order": 1,
        "min_confidence": 30,  # Permissif mais filtré
        "num_predict_override": None,
        "file_extensions": ('.yaml', '.yml', '.json', '.env', '.toml',
                           '.py', '.js', '.ts', '.go', '.java', '.php',
                           '.rb', '.cs', '.c', '.cpp', '.h', '.hpp', 
                           '.rs', '.swift', '.kt', '.scala', '.pl', '.sh', 
                           '.dockerfile', 'Dockerfile', 'docker-compose.yml', 'Makefile'),
        "enable_prudent_detection": True,
        "description_long": "Tout voir (Confiance 30%+, Sévérité Low+)"
    }
}

BUDGET_CONTROLLER = LLMBudgetController()
MODE_CONTROLLER = ScanModeController()

# ==========================================
# 🚫 FICHIERS BUILD-TIME À IGNORER (Rapid/Deep)
# ==========================================
# V2.5: Ces fichiers ne contiennent pas de vulnérabilités applicatives

BUILD_TIME_FILES = {
    'tailwind.config.js',
    'tailwind.config.ts', 
    'postcss.config.js',
    'postcss.config.cjs',
    'vite.config.js',
    'vite.config.ts',
    'webpack.config.js',
    'babel.config.js',
    'jest.config.js',
    'tsconfig.json',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    '.eslintrc.js',
    '.prettierrc',
}

SCAN_EXCLUDE_DIRS = {'node_modules', '.git', 'venv', 'dist', 'build', '__pycache__', '.venv', 'audit_logs', 'reports', 'coverage'}
DEVSECOPS_EXTRA_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}

# ==========================================
# 🚫 VULNÉRABILITÉS IMPOSSIBLES PAR LANGAGE
# ==========================================
# V2.5: Filtre anti-hallucination sémantique

LANGUAGE_FORBIDDEN = {
    "py": ["Buffer Overflow", "Use After Free", "Stack Overflow", "Heap Overflow"],
    "python": ["Buffer Overflow", "Use After Free", "Stack Overflow", "Heap Overflow"],
    "js": ["SQL Injection", "Buffer Overflow", "Use After Free", "Memory Leak"],
    "javascript": ["SQL Injection", "Buffer Overflow", "Use After Free"],
    "ts": ["SQL Injection", "Buffer Overflow", "Use After Free"],
    "typescript": ["SQL Injection", "Buffer Overflow", "Use After Free"],
    "go": ["Buffer Overflow", "Use After Free"],
    "java": ["Buffer Overflow", "Use After Free", "Stack Overflow"],
    "php": ["Buffer Overflow", "Use After Free"],
}

# Termes mous pour réduction de confiance
SOFT_TERMS = [
    "peut-être", "potentiellement", "il semble", "probablement",
    "peut être", "possiblement", "éventuellement", "peut-etre",
    "maybe", "potentially", "seems", "probably", "possibly"
]

# Filtrage incohérences par type de fichier (config files)
SECURITY_FILTERS = {
    "css": ["XSS", "SQL Injection", "SQLi", "RCE", "Command Injection", "Buffer Overflow"],
    "md": ["SQL Injection", "SQLi", "Buffer Overflow", "XSS"],
    "json": ["SQL Injection", "SQLi", "XSS", "RCE", "Command Injection"],
    "yaml": ["XSS", "SQLi"],
    "yml": ["XSS", "SQLi"],
    "txt": ["XSS", "SQLi", "RCE", "Buffer Overflow"],
    "xml": ["SQLi"],
    "html": ["SQLi", "Buffer Overflow"],
    "svg": ["SQLi", "RCE"],
}


# ==========================================
# 🚀 FASTAPI APP
# ==========================================

app = FastAPI(title="Nexus Auditor Enterprise API V3.0 Stable")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 📊 ÉTAT GLOBAL
# ==========================================

scan_state = {
    "id": None,
    "is_scanning": False,
    "start_time": None,
    "current_stage": "idle",
    "stage_report": init_stage_report("idle"),
    "progress": 0,
    "current_file": "",
    "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0, "skipped": 0},
    "logs": [],
    "vulnerabilities": [],
    "should_stop": False,
    "estimated_time": "Calcul...",
    "confidence_score": 0.0,
    "failed_analyses": 0,
    "successful_analyses": 0,
    "target_dir": None,
    "profile": None,
    "mode": None,
    "budget_info": {},
    "preflight": {},
    "telemetry": init_scan_telemetry()
}

class ScanRequest(BaseModel):
    target: str
    profile: str = "balanced"
    mode: str = "deep"
    # Ollama connection method
    ollama_mode: str = "auto"  # "auto" | "remote"
    ollama_url: Optional[str] = None

class FixRequest(BaseModel):
    vuln_id: int

# ==========================================
# 🛠️ UTILITAIRES
# ==========================================

def add_log(msg, type="info", stage: Optional[str] = None, event: Optional[str] = None, **fields):
    ts = datetime.now().strftime("%H:%M:%S")
    safe_msg = redact_sensitive_text(str(msg))
    current_stage = stage or scan_state.get("current_stage") or "unknown"

    structured_payload = {
        "timestamp": datetime.now().isoformat(),
        "level": str(type).lower(),
        "message": safe_msg,
        "stage": current_stage,
        "event": event or "log",
        "scan_id": scan_state.get("id"),
    }
    if fields:
        structured_payload["meta"] = sanitize_for_log(fields)

    if JSON_LOGS_ENABLED:
        print(json.dumps(structured_payload, ensure_ascii=False))
    else:
        print(f"[{ts}] [{type.upper()}] [{current_stage}] {safe_msg}")

    if len(scan_state["logs"]) > 500: 
        scan_state["logs"].pop(0)
    scan_state["logs"].append({"msg": safe_msg, "type": type, "time": ts, "stage": current_stage, "event": event or "log"})

def save_to_history(summary):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f: 
                history = json.load(f)
        except: 
            pass
    
    history.insert(0, summary)
    history = history[:50]
    
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def save_raw_response(filename: str, response_text: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    raw_file = os.path.join(RAW_RESPONSES_DIR, f"{timestamp}_{safe_filename}.json")
    
    try:
        with open(raw_file, 'w', encoding='utf-8') as f:
            f.write(response_text)
    except Exception as e:
        add_log(f"Impossible de sauvegarder réponse brute: {e}", "warning")

def extract_code_context(filepath, line_number, context_lines=5):
    try:
        if not line_number or str(line_number) == "N/A": 
            return "Ligne inconnue."
        line_idx = int(line_number) - 1
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        start = max(0, line_idx - context_lines)
        end = min(len(lines), line_idx + context_lines + 1)
        
        snippet = ""
        for i in range(start, end):
            prefix = ">> " if i == line_idx else "   "
            snippet += f"{prefix}{i+1}: {lines[i]}"
            
        return snippet
    except Exception as e:
        return f"Impossible d'extraire le contexte : {str(e)}"

def extract_json_from_text(text: str) -> list:
    """
    Extrait le premier tableau JSON valide trouvé dans le texte.
    TOUJOURS retourne une liste (vide si échec) pour éviter les crashes.
    """
    if not text or not text.strip():
        return []
    
    # 1. Essai direct
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
        return []
    except:
        pass
    
    # 2. Cherche un tableau JSON [...] avec regex non-greedy
    try:
        # Pattern qui capture le premier tableau JSON complet
        match = re.search(r'\[\s*\{.*?\}\s*\]', text, re.DOTALL)
        if match:
            result = json.loads(match.group(0))
            if isinstance(result, list):
                return result
    except:
        pass
    
    # 3. Cherche un tableau vide []
    if '[]' in text:
        return []
    
    # 4. Cherche dans un bloc ```json ... ```
    try:
        json_block = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', text, re.DOTALL)
        if json_block:
            result = json.loads(json_block.group(1))
            if isinstance(result, list):
                return result
    except:
        pass
    
    # 5. Cherche un objet unique {...} et le wrappe en liste
    try:
        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if match:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict):
                return [obj]
    except:
        pass
    
    # 6. Échec total - retourne liste vide (pas None!)
    add_log(f"⚠️ Impossible d'extraire JSON valide", "warning")
    return []

# ==========================================
# 📍 ECO RULE #6: CALCUL DES LIGNES PAR LE MOTEUR
# ==========================================

def find_code_lines(file_content: str, evidence: str) -> tuple:
    """
    Calcule les numéros de ligne START/END à partir de la preuve.
    V3.1: Support Fuzzy Matching (ignore espaces)
    """
    if not evidence or not file_content:
        return (None, None)
    
    evidence_clean = evidence.strip()
    if not evidence_clean:
        return (None, None)
    
    lines = file_content.split('\n')
    
    # 1. Exact Match (Ligne unique)
    for i, line in enumerate(lines, start=1):
        if evidence_clean in line:
            return (i, i)
    
    # 2. Exact Match (Multi-lignes)
    if evidence_clean in file_content:
        # Trouver l'offset
        start_idx = file_content.find(evidence_clean)
        # Compter les \n avant
        start_line = file_content.count('\n', 0, start_idx) + 1
        end_line = start_line + evidence_clean.count('\n')
        return (start_line, end_line)

    # 3. Fuzzy Match (Ignore Whitespace)
    # C'est coûteux, on le fait seulement si exact match échoue
    ev_normalized = ''.join(evidence_clean.split())
    if len(ev_normalized) < 10: # Trop court pour fuzzy fiable
        return (None, None)
        
    for i in range(len(lines)):
        # Optimisation: Check fenêtre glissante
        # (Complexe à implémenter parfaitement, on fait simple: check ligne par ligne normalisée)
        line_norm = ''.join(lines[i].split())
        if ev_normalized in line_norm:
            return (i + 1, i + 1)
            
    return (None, None)

# ==========================================
# 🎯 FILTRAGE POST-IA (LOGIQUE AUTOUR DU MOTEUR)
# ==========================================
# V3.1: Logique de filtrage unifiée et explicable

def calculate_confidence(vuln: dict, raw_response: str, filepath: str) -> float:
    """Calcule le score de confiance d'une vulnérabilité"""
    score = 100.0
    
    description = vuln.get("description", "").lower()
    for term in SOFT_TERMS:
        if term in description:
            score -= 15
            break
    
    required_fields = ["title", "severity", "line", "description", "fix"]
    completeness = sum(1 for f in required_fields if vuln.get(f)) / len(required_fields)
    score = score * (0.7 + 0.3 * completeness)
    
    line = str(vuln.get("line", "0"))
    if not line.isdigit() or line == "0":
        score -= 10
    
    if "confidence" in vuln and isinstance(vuln["confidence"], (int, float)):
        ai_confidence = vuln["confidence"]
        score = (score + ai_confidence) / 2
    
    file_ext = os.path.splitext(filepath)[1].lstrip('.')
    vuln_type = vuln.get("type", "").upper()
    title = vuln.get("title", "").upper()
    
    if file_ext in SECURITY_FILTERS:
        blocked_types = SECURITY_FILTERS[file_ext]
        for blocked in blocked_types:
            if blocked.upper() in vuln_type or blocked.upper() in title:
                score -= 30
                add_log(f"⚠️ Incohérence: {blocked} dans .{file_ext}", "warning")
    
    return max(0, min(100, score))

def apply_mode_filters(vulns: list, mode_config: dict, filepath: str, file_content: str = None) -> list:
    """
    V2.5: Filtrage POST-IA strict avec validation de preuve réelle.
    C'est ici que la logique produit s'applique, PAS dans le prompt.
    """
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    
    # V3.0 DEBUG: Log avant filtrage
    add_log(f"🔍 FILTRAGE: {len(vulns)} vulns brutes reçues pour {os.path.basename(filepath)}", "info")
    if vulns:
        add_log(f"  Exemple: {vulns[0].get('title', 'N/A')} (sev={vulns[0].get('severity')}, conf={vulns[0].get('confidence')}%)", "info")
    min_sev = severity_order.get(mode_config["min_severity"], 0)
    min_conf = mode_config["min_confidence"]
    
    # Lire le contenu du fichier si non fourni (pour validation evidence)
    if file_content is None:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        except:
            file_content = ""
    
    file_ext = os.path.splitext(filepath)[1].lstrip('.').lower()
    
    # V3.1: FILTRAGE INTELLIGENT & EXPLICABLE
    filtered = []
    mode_key = mode_config.get("label", "Unknown").lower()
    
    for v in vulns:
        title = v.get('title', 'N/A')
        vuln_type = v.get('type', '').upper()
        
        # 1. Normalisation Sévérité
        raw_severity = v.get("severity", "Unknown") # V3.1 FIX: Unknown par défaut (était Low)
        normalized_severity = raw_severity.strip().capitalize() if isinstance(raw_severity, str) else "Unknown"
        if normalized_severity not in severity_order:
            if normalized_severity == "Unknown":
                pass # Conserver Unknown
            else:
                normalized_severity = "Low" # Fallback pour typos seulement
        v["severity"] = normalized_severity
        
        vuln_sev_val = severity_order.get(normalized_severity, 1)
        vuln_conf = v.get("confidence", 0)
        
        # 2. Filtre Sévérité
        if vuln_sev_val < min_sev:
            # Exception : Ne jamais filtrer SQLi/RCE même si sev estimée basse (sauf Rapid)
            critical_types = ["SQL", "INJECTION", "RCE", "COMMAND", "XSS", "DESERIAL"]
            is_critical_type = any(ct in vuln_type for ct in critical_types) or any(ct in title.upper() for ct in critical_types)
            
            # V3.1 FIX: Ne pas filtrer si Unknown mais type critique
            if is_critical_type and "rapid" not in mode_key:
                 add_log(f"⚠️ Force Keep: {title} (Type Critique malgré Sévérité {normalized_severity})", "warning")
            else:
                add_log(f"🗑️ Filtered: {title} | severity={normalized_severity} | reason=min_severity<{mode_config['min_severity']} ({mode_key})", "info")
                continue

        # 3. Filtre Confiance & Détection Prudente (FIX: Rejeter si confidence=0)
        if vuln_conf == 0 and "confidence" not in v: 
             # Cas "Ghost Profile" : pas de confiance fournie par l'IA
             add_log(f"🗑️ Filtered: {title} | reason=no_confidence_provided", "info")
             continue

        is_prudent = False
        if vuln_conf < min_conf:
            # Check Prudent Detection (Scope 35-50% généralement)
            if mode_config.get("enable_prudent_detection", False):
                if 35 <= vuln_conf < 50:
                    critical_types = ["SQL", "INJECTION", "RCE", "COMMAND", "XSS", "BUFFER", "OVERFLOW", "DESERIAL"]
                    is_critical_type = any(ct in vuln_type for ct in critical_types) or any(ct in title.upper() for ct in critical_types)
                    
                    if is_critical_type:
                        is_prudent = True
                        v["prudent_detection"] = True
                        v["note"] = "Review Required (Low Confidence 35-50%)"
                        add_log(f"⚠️ Prudent detection: {title} | confidence={vuln_conf} | manual review", "warning")
            
            if not is_prudent:
                add_log(f"🗑️ Filtered: {title} | confidence={vuln_conf} | reason=min_confidence<{min_conf} ({mode_key})", "info")
                continue
        
        
        # ==========================================
        # FILTRE 3: V2.5 - Preuve selon le mode
        # RAPID = preuve textuelle stricte
        # DEEP/DEVSECOPS = preuve structurelle (ligne/fonction/variable)
        # ==========================================
        evidence = v.get("evidence", v.get("snippet", ""))
        line_num = v.get("line")
        mode_label = mode_config.get("label", "")
        
        if "Rapide" in mode_label or "rapid" in mode_label.lower():
            # 🔒 RAPID: Preuve textuelle stricte obligatoire
            if evidence and file_content:
                # V3.1: Sécuriser type evidence
                if isinstance(evidence, list): evidence = evidence[0] if evidence else ""
                if not isinstance(evidence, str): evidence = str(evidence)
                
                evidence_clean = evidence.strip()
                if len(evidence_clean) > 10 and evidence_clean not in file_content:
                    evidence_normalized = ' '.join(evidence_clean.split())
                    file_normalized = ' '.join(file_content.split())
                    if evidence_normalized not in file_normalized:
                        # V3.1 FIX: RESCUE HIGH/CRITICAL IF PROOF MISSING
                        if vuln_sev_val >= 3: # High or Critical
                            v["evidence_missing"] = True
                            v["needs_manual_review"] = True
                            v["note"] = "Evidence missing: verify manually (High Severity preserved)"
                            add_log(f"⚠️ Rescue: {title} | reason=high_severity_proof_missing", "warning")
                        else:
                            add_log(f"🗑️ Filtered: {title} | reason=proof_missing ({mode_key})", "info")
                            continue
        else:
            # 🧠 DEEP/DEVSECOPS: Preuve structurelle
            # Accepté si: line existe OU evidence partielle OU référence fonction/variable
            has_valid_proof = False
            
            # Check 1: Le numéro de ligne existe dans le fichier
            if line_num and isinstance(line_num, int) and line_num > 0:
                file_lines = file_content.split('\n') if file_content else []
                if line_num <= len(file_lines):
                    has_valid_proof = True
            
            # Check 2: Au moins une partie de l'evidence existe (mots-clés)
            if not has_valid_proof and evidence and file_content:
                # Extraire les identifiants (noms de fonctions, variables)
                identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b', evidence)
                if identifiers:
                    # Au moins 1 identifiant suffit en Deep/DevSecOps si longueur > 4
                    matches = sum(1 for ident in identifiers if ident in file_content)
                    if matches >= 1:
                        has_valid_proof = True
            
            # Check 3: Preuve textuelle exacte (bonus)
            if not has_valid_proof and evidence and file_content:
                # V3.1: Sécuriser type evidence
                if isinstance(evidence, list): evidence = evidence[0] if evidence else ""
                if not isinstance(evidence, str): evidence = str(evidence)

                evidence_clean = evidence.strip()
                if len(evidence_clean) > 5 and evidence_clean in file_content:
                    has_valid_proof = True
            
            # Si aucune preuve valide en Deep, on filtre (mais moins strict qu'en Rapid)
            if not has_valid_proof and evidence:
                # V3.1 FIX: RESCUE HIGH/CRITICAL IF PROOF MISSING
                if vuln_sev_val >= 3: # High or Critical
                    v["evidence_missing"] = True
                    v["needs_manual_review"] = True
                    v["note"] = "Evidence missing: verify manually (High Severity preserved)"
                    add_log(f"⚠️ Rescue: {title} | reason=high_severity_proof_missing", "warning")
                else:
                    add_log(f"🗑️ Filtered: {title} | reason=structural_proof_failed ({mode_key})", "info")
                    continue
        
        # ==========================================
        # FILTRE 4: V2.5 - Vulnérabilités impossibles par langage
        # ==========================================
        if file_ext in LANGUAGE_FORBIDDEN:
            forbidden_types = LANGUAGE_FORBIDDEN[file_ext]
            is_forbidden = False
            for forbidden in forbidden_types:
                if forbidden.upper() in vuln_type or forbidden.upper() in title.upper():
                    add_log(f"�️ Filtered: {title} | reason=impossible_in_{file_ext} ({forbidden})", "info")
                    is_forbidden = True
                    break
            if is_forbidden:
                continue
        
        filtered.append(v)
    
    # ==========================================
    # FILTRE 5: Limite par fichier
    # ==========================================
    max_vulns = mode_config.get("max_vulns_per_file")
    if max_vulns and len(filtered) > max_vulns:
        add_log(f"✂️ Limité à {max_vulns} vulns pour {os.path.basename(filepath)}", "info")
        # Trier par sévérité descendante avant de limiter
        filtered.sort(key=lambda x: severity_order.get(x.get("severity", "Low"), 0), reverse=True)
        filtered = filtered[:max_vulns]
    
    return filtered


def normalize_vulnerability(vuln: dict, filepath: str, filename: str, raw_response: str, file_content: str = None) -> dict:
    """
    ECO: Normalise avec calcul de lignes par le moteur et politique de sévérité.
    V3.1: Force Types Regex (SQLi, XSS, RCE...) pour crédibilité maximale.
    """
    # Lire le contenu si non fourni
    if file_content is None:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        except:
            file_content = ""
    
    # Evidence (preuve)
    evidence = vuln.get("evidence", vuln.get("snippet", ""))
    
    # V3.1: Sécuriser type evidence (si liste retournée par IA)
    if isinstance(evidence, list): 
        evidence = evidence[0] if evidence else ""
    if not isinstance(evidence, str):
        evidence = str(evidence)
    
    # ECO RULE #6: Calculer les lignes à partir de l'evidence
    line_start, line_end = find_code_lines(file_content, evidence)
    
    # Fallback: Si le moteur trouve pas, utiliser la ligne de l'IA (avec méfiance)
    if line_start is None:
        line_ai = vuln.get("line", "0")
        line_clean = ''.join(filter(str.isdigit, str(line_ai)))
        if line_clean and line_clean != "0":
            line_start = int(line_clean)
            line_end = line_start
    
    # Snippet de code
    snippet = evidence if evidence else extract_code_context(filepath, str(line_start)) if line_start else "Code non disponible"
    
    # V3.1: Normalisation Types & Sévérités par REGEX
    title = str(vuln.get("title", "")).strip()
    vtype = str(vuln.get("type", "")).strip().upper()
    desc = str(vuln.get("description", "")).strip().lower()
    
    # Concatener pour recherche de mots-clés
    full_text = (title + " " + vtype + " " + desc).lower()
    
    final_type = vtype
    min_sev_forced = None
    
    # Règles de forcing strictes
    if "sql" in full_text and "inject" in full_text:
        final_type = "SQL_INJECTION"
        min_sev_forced = "High"
    elif ("xss" in full_text) or ("cross-site" in full_text and "script" in full_text):
        final_type = "XSS"
        min_sev_forced = "Medium" # Peut être Low (Reflected) ou High (Stored)
    elif ("remote code" in full_text) or ("command" in full_text and "inject" in full_text):
        final_type = "RCE"
        min_sev_forced = "Critical"
    elif "deserial" in full_text:
        final_type = "DESERIALIZATION"
        min_sev_forced = "High"
    elif ("hardcoded" in full_text or "clear text" in full_text) and ("password" in full_text or "token" in full_text or "key" in full_text):
        final_type = "HARDCODED_SECRET"
        min_sev_forced = "High"
    elif "path traversal" in full_text or "directory traversal" in full_text:
        final_type = "PATH_TRAVERSAL"
        min_sev_forced = "Medium"
        
    # V3.1: Confiance absolue en l'IA pour la sévérité initiale (normalisée)
    raw_sev = vuln.get("severity", "Unknown") # V3.1 FIX: Unknown par défaut
    if isinstance(raw_sev, list): 
        raw_sev = raw_sev[0] if raw_sev else "Unknown"
    
    sev_raw = str(raw_sev).strip().capitalize()
    
    # Forcing sévérité minimale si type critique détecté
    if min_sev_forced:
        sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        current_val = sev_map.get(sev_raw, 1)
        forced_val = sev_map.get(min_sev_forced, 1)
        if forced_val > current_val:
            sev_raw = min_sev_forced

    if "crit" in sev_raw.lower(): sev = "Critical"
    elif "high" in sev_raw.lower(): sev = "High"
    elif "med" in sev_raw.lower(): sev = "Medium"
    elif "low" in sev_raw.lower(): sev = "Low"
    else: sev = "Unknown" # V3.1 FIX: Unknown par défaut au lieu de Low
    
    # V3.1 FIX: Strict confidence handling (0 si absent)
    if "confidence" in vuln:
        confidence = calculate_confidence(vuln, raw_response, filepath)
    else:
        confidence = 0.0 # Force 0 pour éviter les hallucinations non-confiantes

    # V3.1 FIX: Fallback Description/Fix
    final_desc = desc if desc and len(desc) > 5 else title
    if not final_desc: final_desc = f"Potentielle vulnérabilité : {final_type}"
    
    final_fix = vuln.get("fix", vuln.get("recommendation", ""))
    if not final_fix: final_fix = "Voir les recommandations de sécurité standard pour ce type."
    
    normalized = {
        "file": filename,
        "filepath": filepath,
        "title": title if title else final_type,
        "severity": sev,
        "line": line_start,
        "line_end": line_end,
        "evidence": evidence,
        "description": final_desc,
        "fix": final_fix,
        "confidence": round(confidence, 2),
        "snippet": snippet,
        "type": final_type,
        "impact": vuln.get("impact", "Non évalué"),
        "timestamp": datetime.now().isoformat(),
        # V3.1 Flags potentiels
        "evidence_missing": False,
        "needs_manual_review": False
    }
    return ensure_proof(normalized)


# ==========================================
# 🔧 AUTO-FIX ENGINE
# ==========================================

def generate_fix_patch(vuln: dict) -> Optional[dict]:
    """Génère un patch Git pour corriger une vulnérabilité"""
    try:
        filepath = vuln.get("filepath")
        line = vuln.get("line") or vuln.get("line_start")  # ECO: Fallback to line_start
        fix_code = vuln.get("fix", "")
        
        if not filepath or not os.path.exists(filepath):
            return {"success": False, "error": "Fichier introuvable"}
        
        if not line or not fix_code:
            return {"success": False, "error": "Informations insuffisantes"}
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_lines = f.readlines()
        
        modified_lines = original_lines.copy()
        vuln_line_idx = line - 1
        
        if vuln_line_idx < 0 or vuln_line_idx >= len(original_lines):
            return {"success": False, "error": "Numéro de ligne invalide"}
        
        fix_lines = fix_code.strip().split('\n')
        indent = len(original_lines[vuln_line_idx]) - len(original_lines[vuln_line_idx].lstrip())
        indent_str = ' ' * indent
        
        fixed_lines = [indent_str + l.lstrip() + '\n' for l in fix_lines]
        modified_lines[vuln_line_idx:vuln_line_idx+1] = fixed_lines
        
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{vuln['file']}",
            tofile=f"b/{vuln['file']}",
            lineterm=''
        )
        
        diff_text = '\n'.join(diff)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        patch_filename = f"patch_{vuln['id']}_{timestamp}.patch"
        patch_path = os.path.join(PATCHES_DIR, patch_filename)
        
        with open(patch_path, 'w', encoding='utf-8') as f:
            f.write(diff_text)
        
        return {
            "success": True,
            "patch_file": patch_filename,
            "patch_path": patch_path,
            "diff": diff_text,
            "preview": {
                "before": original_lines[vuln_line_idx].strip(),
                "after": ''.join(fixed_lines).strip()
            }
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# ==========================================
# 🧠 MOTEUR IA STABLE (V2.2 BASE)
# ==========================================

class StableEngine:
    """
    Moteur IA basé sur V2.2 - Simple, prévisible, stable.
    1 appel IA = 1 analyse simple
    """
    
    def __init__(
        self,
        profile_config: dict,
        mode_config: dict,
        budget_plan: Optional[dict] = None,
        ollama_base_url: str = None,
        profile_name: str = "balanced",
    ):
        self.profile = profile_config
        self.mode = mode_config
        self.fallback_model = "qwen2.5-coder:7b"  # V2.5: Fallback cohérent
        self.budget_plan = budget_plan or {}
        self.profile_name = profile_name or str(self.budget_plan.get("profile") or "balanced")
        self.ollama_base_url = ollama_base_url or OLLAMA_BASE_URL  # Custom ou défaut

    def _build_llm_options(
        self,
        max_output_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None
    ) -> dict:
        return {
            "temperature": float(temperature if temperature is not None else self.budget_plan.get("temperature", 0.1)),
            "top_p": float(top_p if top_p is not None else self.budget_plan.get("top_p", 0.9)),
            "num_ctx": int(self.budget_plan.get("max_context_tokens", self.profile.get("num_ctx", 8192))),
            "num_predict": int(max_output_tokens if max_output_tokens is not None else self.budget_plan.get("max_output_tokens", self.profile.get("num_predict", 1024))),
        }

    def _should_early_exit(self, current_findings: list) -> bool:
        strategy = self.budget_plan.get("early_exit_strategy", "none")
        if strategy != "first_high_confidence":
            return False

        threshold = int(self.budget_plan.get("early_exit_confidence", 60))
        for finding in current_findings:
            severity = str(finding.get("severity", "")).lower()
            confidence = float(finding.get("confidence", 0))
            if severity in {"critical", "high"} and confidence >= threshold:
                return True
        return False

    def _verify_findings_for_chunk(self, filename: str, chunk: str, findings: list, chunk_index: int, chunk_total: int) -> list:
        if not findings or not self.budget_plan.get("enable_verify_pass", False):
            return findings

        candidates = []
        for idx, finding in enumerate(findings):
            candidates.append({
                "idx": idx,
                "title": finding.get("title"),
                "type": finding.get("type"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "line": finding.get("line"),
                "evidence": str(finding.get("evidence", ""))[:300],
            })

        verify_prompt = VERIFY_PROMPT.format(
            filename=f"{filename} (part {chunk_index}/{chunk_total})",
            candidates_json=json.dumps(candidates, ensure_ascii=False),
            content=chunk[:16000],
        )

        verify_result = self.call_ollama(
            verify_prompt,
            filename=filename,
            max_retries=self.budget_plan.get("verify_retries", 1),
            chunk_index=chunk_index,
            chunk_total=chunk_total,
            purpose="verify",
            max_output_tokens=self.budget_plan.get("verify_max_output_tokens", 512),
            temperature=float(self.budget_plan.get("verify_temperature", 0.0)),
            top_p=float(self.budget_plan.get("verify_top_p", 0.7)),
        )

        if not verify_result or not isinstance(verify_result.get("data"), list):
            return findings

        verdicts = {}
        for item in verify_result["data"]:
            if not isinstance(item, dict):
                continue
            idx = item.get("idx")
            if not isinstance(idx, int):
                continue
            verdicts[idx] = item

        adjusted = []
        for idx, finding in enumerate(findings):
            verdict = verdicts.get(idx)
            if not verdict:
                finding["verification_status"] = "unverified"
                adjusted.append(finding)
                continue

            verdict_type = str(verdict.get("verdict", "")).lower()
            reason = str(verdict.get("reason", "")).strip()
            delta_raw = verdict.get("confidence_adjustment", 0)
            try:
                delta = int(delta_raw)
            except Exception:
                delta = 0
            delta = max(-30, min(10, delta))

            if verdict_type == "reject":
                continue

            if verdict_type == "uncertain":
                delta = min(delta, -10)
                finding["note"] = f"Verify pass: uncertain. {reason}".strip()
                finding["needs_manual_review"] = True

            if verdict_type == "confirm":
                finding["note"] = f"Verify pass: confirmed. {reason}".strip()

            finding["verification_status"] = verdict_type if verdict_type in {"confirm", "uncertain"} else "unverified"
            finding["confidence"] = round(max(0.0, min(100.0, float(finding.get("confidence", 0.0)) + delta)), 2)
            adjusted.append(finding)

        return adjusted

    def call_ollama(
        self,
        prompt: str,
        filename: str,
        max_retries: Optional[int] = None,
        chunk_index: Optional[int] = None,
        chunk_total: Optional[int] = None,
        purpose: str = "analysis",
        max_output_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
    ) -> Optional[dict]:
        """Appel IA simple avec retry et fallback"""
        timeout = int(self.budget_plan.get("timeout_s", self.profile.get("timeout", 180)))
        model = self.profile["model"]

        if max_retries is None:
            max_retries = int(self.budget_plan.get("retries", 1))
        max_retries = max(1, int(max_retries))
        backoff_factor = float(self.budget_plan.get("retry_backoff_factor", 1.5))

        llm_options = self._build_llm_options(
            max_output_tokens=max_output_tokens,
            temperature=temperature,
            top_p=top_p,
        )

        for attempt in range(max_retries):
            request_start = time.time()
            request_success = False
            status_code = None
            error_reason = None
            try:
                if attempt > 0:
                    add_log(f"🔄 Retry {attempt+1}/{max_retries} pour {filename}", "warning")
                    time.sleep(backoff_factor ** attempt)
                
                chunk_label = f" chunk {chunk_index}/{chunk_total}" if chunk_index and chunk_total else ""
                add_log(
                    f"🤖 {purpose.capitalize()}: {filename}{chunk_label} (modèle: {model})",
                    "info",
                    stage="analyze",
                    event="llm_dispatch",
                    filename=filename,
                    chunk_index=chunk_index,
                    chunk_total=chunk_total,
                    model=model,
                    purpose=purpose,
                    options=llm_options,
                )
                
                response = requests.post(
                    f"{self.ollama_base_url}/api/generate",  # V2.5: URL dynamique selon mode
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": llm_options
                    },
                    timeout=timeout
                )
                status_code = response.status_code
                
                if response.status_code == 200:
                    raw_text = response.json().get('response', '{}')
                    save_raw_response(filename, raw_text)
                    
                    parsed = extract_json_from_text(raw_text)
                    
                    if parsed is not None:
                        request_success = True
                        add_log(f"✅ Réponse valide pour {filename}", "success")
                        return {"data": parsed, "raw": raw_text}
                    else:
                        error_reason = "invalid_json"
                        add_log(f"⚠️ JSON invalide pour {filename}", "warning")
                        continue
                else:
                    error_reason = f"http_{response.status_code}"
                    add_log(f"❌ HTTP {response.status_code} pour {filename}", "error")
                    
            except requests.exceptions.Timeout:
                error_reason = "timeout"
                add_log(f"⏱️ Timeout ({timeout}s) pour {filename}", "warning")
            except Exception as e:
                error_reason = type(e).__name__
                add_log(f"❌ Erreur: {str(e)[:100]}", "error")
            finally:
                latency_ms = round((time.time() - request_start) * 1000, 2)
                record_llm_call_metrics(
                    filename=filename,
                    latency_ms=latency_ms,
                    success=request_success,
                    attempt=attempt + 1,
                    chunk_index=chunk_index,
                    chunk_total=chunk_total,
                    status_code=status_code,
                    error=error_reason,
                )
        
        # ECO RULE #1: Pas de fallback retry - 1 fichier = 1 appel
        return None


    def scan_file(self, filepath: str, filename: str, analysis_context: Optional[dict] = None) -> list:
        """
        V3.1 SMART CHUNKING STRATEGY:
        - Si len < ctx: Envoi complet (1 pass).
        - Si len > ctx: Découpage intelligent.
        - Rapid Mode: Max 1 chunk (head).
        - Deep Mode: Max 2 chunks (head + mid).
        - Timeout strict par fichier.
        """
        if scan_state["should_stop"]:
            return []

        try:
            analysis_context = analysis_context or {}
            mode_key = MODE_CONTROLLER.resolve_mode_key(
                mode_key=analysis_context.get("mode_key"),
                mode_config=self.mode,
            )
            hotspot_reasons = analysis_context.get("hotspot_reasons", [])
            cross_file_hints = analysis_context.get("cross_file_hints", [])

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return []

            chunk_plan = build_chunk_plan(content, filepath, self.profile, self.mode)
            chunk_infos = chunk_plan.get("chunks", [])
            chunk_entries = [c for c in chunk_infos if c.get("content", "").strip()]
            chunks = [c.get("content", "") for c in chunk_entries]
            if not chunks:
                return []

            chunk_token_estimates = [int(c.get("tokens_estimated", estimate_tokens_from_text(c.get("content", "")))) for c in chunk_entries]
            strategy = chunk_plan.get("strategy", "unknown")
            language = chunk_plan.get("language", "unknown")
            token_budget = int(chunk_plan.get("token_budget", 0))
            overlap_tokens = int(chunk_plan.get("overlap_tokens", 0))
            max_chunks = int(chunk_plan.get("max_chunks", len(chunks)))

            if len(chunks) >= max_chunks and estimate_tokens_from_text(content) > token_budget:
                add_log(
                    f"✂️ Limite chunks atteinte ({max_chunks}) pour {filename}",
                    "info",
                    stage="analyze",
                    event="chunk_limit_hit",
                    filename=filename,
                    max_chunks=max_chunks,
                )
            
            scan_state["current_file"] = filename
            all_vulns = []

            telemetry = scan_state.setdefault("telemetry", init_scan_telemetry())
            total_chunk_tokens = sum(chunk_token_estimates)
            telemetry["chunks_total"] += len(chunks)
            telemetry["chunks_by_file"][filename] = len(chunks)
            telemetry["tokens_estimated_by_file"][filename] = total_chunk_tokens
            telemetry["tokens_estimated_total"] += total_chunk_tokens
            add_log(
                f"📦 {filename}: {len(chunks)} chunk(s), ~{total_chunk_tokens} tokens estimés ({strategy}/{language})",
                "info",
                stage="analyze",
                event="chunk_plan",
                filename=filename,
                chunks=len(chunks),
                tokens_estimated=total_chunk_tokens,
                strategy=strategy,
                language=language,
                chunk_token_budget=token_budget,
                overlap_tokens=overlap_tokens,
            )
            
            file_start_global = time.time()
            max_time = self.mode.get("max_time_per_file", 60)

            # --- ANALYSE CHUNK PAR CHUNK ---
            for i, chunk in enumerate(chunks):
                # Check Global Stop
                if scan_state["should_stop"]: 
                    return []
                
                # Check File Timeout
                if (time.time() - file_start_global) > max_time:
                    add_log(f"⏱️ Timeout fichier atteint ({max_time}s) - Arrêt analyse {filename}", "warning")
                    break

                chunk_tokens = chunk_token_estimates[i] if i < len(chunk_token_estimates) else estimate_tokens_from_text(chunk)
                telemetry["chunks_processed"] += 1
                add_log(
                    f"🔎 Chunk {i+1}/{len(chunks)} (~{chunk_tokens} tokens) pour {filename}",
                    "info",
                    stage="analyze",
                    event="chunk_start",
                    filename=filename,
                    chunk_index=i + 1,
                    chunk_total=len(chunks),
                    chunk_tokens_estimated=chunk_tokens,
                )

                prompt = MODE_CONTROLLER.build_analysis_prompt(
                    mode_key=mode_key,
                    filename=f"{filename} (part {i+1}/{len(chunks)})",
                    content=chunk,
                    language=language,
                    chunk_index=i + 1,
                    chunk_total=len(chunks),
                    hotspot_reasons=hotspot_reasons,
                    cross_file_hints=cross_file_hints,
                )
                
                # Call Ollama
                result = self.call_ollama(
                    prompt,
                    filename,
                    max_retries=self.budget_plan.get("retries"),
                    chunk_index=i + 1,
                    chunk_total=len(chunks),
                )
                
                if result:
                    data = result["data"]
                    raw_response = result["raw"]
                    
                    if isinstance(data, dict): data = [data]
                    if isinstance(data, list):
                        normalized_chunk_findings = []
                        for v in data:
                            if not isinstance(v, dict): continue
                            
                            # Normalisation (V3.1: Pass full content for line finding)
                            normalized = normalize_vulnerability(v, filepath, filename, raw_response, content)
                            normalized["chunk_index"] = i + 1
                            normalized["chunk_total"] = len(chunks)
                            normalized["chunk_refs"] = [i + 1]
                            
                            # Ajustement confiance si chunk partiel
                            if len(chunks) > 1:
                                normalized["confidence"] = min(normalized["confidence"], 90)

                            normalized_chunk_findings.append(normalized)

                        if normalized_chunk_findings and self.budget_plan.get("enable_verify_pass", False):
                            normalized_chunk_findings = self._verify_findings_for_chunk(
                                filename=filename,
                                chunk=chunk,
                                findings=normalized_chunk_findings,
                                chunk_index=i + 1,
                                chunk_total=len(chunks),
                            )

                        all_vulns.extend(normalized_chunk_findings)
                        
                        scan_state["successful_analyses"] += 1

                        if self._should_early_exit(normalized_chunk_findings):
                            add_log(
                                f"⚡ Early-exit activé pour {filename} (finding critique confirmé)",
                                "info",
                                stage="analyze",
                                event="early_exit",
                                filename=filename,
                                strategy=self.budget_plan.get("early_exit_strategy"),
                            )
                            break
                else:
                    scan_state["failed_analyses"] += 1

            # --- V3.1 RESCUE PASS (DEEP/DEVSECOPS ONLY) ---
            # Si 0 findings sur un fichier critique en mode approfondi, on revérifie si on a raté un truc évident
            # (Limité pour ne pas exploser le temps)
            if not all_vulns and self.mode["label"] in ["Scan Profond", "DevSecOps (CI/CD)"]:
                is_risky_file = filename.endswith(('.js', '.ts', '.py', '.php', '.java'))
                time_left = max_time - (time.time() - file_start_global)
                
                if is_risky_file and time_left > 15:
                    # On ne relance pas une analyse complète (trop cher), mais on loggue pour info
                    # Future: Pourrait relancer avec prompt "Check specifically for X"
                    pass 
            
            # Filtrage POST-IA selon le mode (avec contenu pour validation preuve)
            add_log(f"🔄 Post-processing: {len(all_vulns)} findings bruts", "info")
            filtered_vulns = apply_mode_filters(all_vulns, self.mode, filepath, content)
            deduped_vulns = aggregate_findings(
                filtered_vulns,
                profile_key=self.profile_name,
                verify_expected=bool(self.budget_plan.get("enable_verify_pass", False)),
            )
            if len(deduped_vulns) != len(filtered_vulns):
                add_log(
                    f"🧩 Dedup/Merge: {len(filtered_vulns)} -> {len(deduped_vulns)} findings ({filename})",
                    "info",
                    stage="correlate",
                    event="dedup_merge",
                    filename=filename,
                    before=len(filtered_vulns),
                    after=len(deduped_vulns),
                )

            return deduped_vulns


        except Exception as e:
            add_log(f"❌ Erreur analyse {filename}: {e}", "error")
            scan_state["failed_analyses"] += 1
            return []


# ==========================================
# 📐 PREFLIGHT + ESTIMATION
# ==========================================

def format_duration(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_bytes(value: int) -> str:
    size = float(max(0, int(value)))
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    precision = 0 if idx == 0 else 2
    return f"{size:.{precision}f} {units[idx]}"


def should_scan_file(filename: str, resolved_mode_key: str, extensions: Tuple[str, ...]) -> bool:
    if resolved_mode_key in ("rapid", "deep") and filename in BUILD_TIME_FILES:
        return False
    if filename.endswith(extensions):
        return True
    if resolved_mode_key == "devsecops" and filename in DEVSECOPS_EXTRA_FILENAMES:
        return True
    return False


def collect_scan_candidates(target_dir: str, resolved_mode_key: str, mode_config: Dict[str, Any]) -> Dict[str, Any]:
    extensions = tuple(mode_config.get("file_extensions") or ())
    discovered_files: List[str] = []
    file_sizes: Dict[str, int] = {}

    for root, dirs, filenames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SCAN_EXCLUDE_DIRS]
        for filename in filenames:
            if not should_scan_file(filename, resolved_mode_key, extensions):
                continue
            full_path = os.path.join(root, filename)
            discovered_files.append(full_path)
            try:
                file_sizes[full_path] = max(0, int(os.path.getsize(full_path)))
            except OSError:
                file_sizes[full_path] = 0

    prioritized_entries = MODE_CONTROLLER.prioritize_files(discovered_files, resolved_mode_key)
    files_discovered = len(prioritized_entries)

    max_files = mode_config.get("max_files")
    files_skipped = 0
    if max_files and files_discovered > max_files:
        files_skipped = files_discovered - max_files
        prioritized_entries = prioritized_entries[:max_files]

    scheduled_paths = [entry.get("path") for entry in prioritized_entries if entry.get("path")]
    bytes_discovered = sum(file_sizes.get(path, 0) for path in discovered_files)
    bytes_scheduled = sum(file_sizes.get(path, 0) for path in scheduled_paths)

    return {
        "file_entries": prioritized_entries,
        "file_sizes": file_sizes,
        "files_discovered": files_discovered,
        "files_scheduled": len(prioritized_entries),
        "files_skipped": files_skipped,
        "bytes_discovered": bytes_discovered,
        "bytes_scheduled": bytes_scheduled,
    }


def _estimate_tokens_and_chunks(file_sizes: Dict[str, int], chunk_budget_tokens: int, max_chunks_per_file: int) -> Tuple[int, int]:
    token_budget = max(1, int(chunk_budget_tokens))
    max_chunks = max(1, int(max_chunks_per_file))
    tokens_total = 0
    chunks_total = 0

    for size in file_sizes.values():
        if size <= 0:
            continue
        est_tokens = max(1, int(size / 4))
        tokens_total += est_tokens
        needed_chunks = 1 if est_tokens <= token_budget else int(math.ceil(est_tokens / token_budget))
        chunks_total += max(1, min(max_chunks, needed_chunks))

    return tokens_total, chunks_total


def build_scan_preflight(
    target: str,
    profile_key: str,
    mode_key: str,
    ollama_mode: str = "auto",
    ollama_url: Optional[str] = None,
) -> Dict[str, Any]:
    profile = POWER_PROFILES.get(profile_key, POWER_PROFILES["balanced"])
    mode = SCAN_MODES.get(mode_key, SCAN_MODES["deep"])
    resolved_mode_key = MODE_CONTROLLER.resolve_mode_key(mode_key=mode_key, mode_config=mode)
    resolved_ollama_base = get_ollama_base_url(ollama_mode=ollama_mode, ollama_url=ollama_url)
    llm_plan = BUDGET_CONTROLLER.compute_plan(
        profile_key=profile_key,
        mode_key=resolved_mode_key,
        profile_config=profile,
        mode_config=mode,
        ollama_mode=ollama_mode,
    )

    tmp_dir = None
    target_dir = target
    cloned_repo = False

    try:
        if target.startswith(("http", "git@")):
            tmp_dir = tempfile.mkdtemp(prefix="nexus_preflight_")
            Repo.clone_from(target, tmp_dir)
            target_dir = tmp_dir
            cloned_repo = True

        collected = collect_scan_candidates(target_dir, resolved_mode_key, mode)
        scheduled_size_map = {
            entry["path"]: collected["file_sizes"].get(entry["path"], 0)
            for entry in collected["file_entries"]
            if entry.get("path")
        }

        chunk_budget = compute_chunk_token_budget(profile, mode)
        max_chunks = resolve_max_chunks(mode)
        tokens_estimated, chunks_estimated = _estimate_tokens_and_chunks(
            scheduled_size_map,
            chunk_budget_tokens=chunk_budget,
            max_chunks_per_file=max_chunks,
        )

        context_factor = float(llm_plan.get("max_context_tokens", 8192)) / 8192.0
        output_factor = float(llm_plan.get("max_output_tokens", 1024)) / 1024.0
        mode_factor = {"rapid": 0.78, "deep": 1.0, "devsecops": 1.18}.get(resolved_mode_key, 1.0)
        remote_factor = 1.32 if ollama_mode == "remote" else 1.0
        pass_factor = max(1, int(llm_plan.get("analysis_passes", 1)))
        per_chunk_seconds = (1.7 + (context_factor * 0.65) + (output_factor * 0.35)) * mode_factor * remote_factor
        per_chunk_seconds = max(1.0, min(per_chunk_seconds, float(llm_plan.get("timeout_s", 90)) * 0.75))

        analyze_eta = 0.0
        if chunks_estimated > 0:
            concurrency = max(1, int(llm_plan.get("concurrency", 1)))
            analyze_eta = (chunks_estimated * per_chunk_seconds * pass_factor) / concurrency

        stage_estimates_s = {
            "normalize": round(2.0 if cloned_repo else 0.30, 2),
            "index": round(max(0.15, collected["files_discovered"] * 0.01), 2),
            "analyze": round(analyze_eta, 2),
            "correlate": round(max(0.20, collected["files_scheduled"] * 0.02), 2),
            "report": round(max(0.15, collected["files_scheduled"] * 0.01), 2),
        }
        eta_seconds = round(sum(stage_estimates_s.values()), 2)

        return {
            "generated_at": datetime.now().isoformat(),
            "target": target,
            "target_dir": target_dir,
            "profile": profile_key,
            "mode": resolved_mode_key,
            "ollama_mode": ollama_mode,
            "ollama_url": resolved_ollama_base,
            "stage_sequence": list(PIPELINE_STAGES),
            "files": {
                "discovered": collected["files_discovered"],
                "scheduled": collected["files_scheduled"],
                "skipped": collected["files_skipped"],
            },
            "size": {
                "discovered_bytes": collected["bytes_discovered"],
                "scheduled_bytes": collected["bytes_scheduled"],
                "discovered_human": format_bytes(collected["bytes_discovered"]),
                "scheduled_human": format_bytes(collected["bytes_scheduled"]),
            },
            "llm_plan": {
                "max_context_tokens": llm_plan.get("max_context_tokens"),
                "max_output_tokens": llm_plan.get("max_output_tokens"),
                "concurrency": llm_plan.get("concurrency"),
                "analysis_passes": llm_plan.get("analysis_passes"),
                "timeout_s": llm_plan.get("timeout_s"),
            },
            "chunking": {
                "chunk_token_budget": chunk_budget,
                "max_chunks_per_file": max_chunks,
                "tokens_estimated_total": tokens_estimated,
                "chunks_estimated_total": chunks_estimated,
            },
            "eta": {
                "seconds": eta_seconds,
                "human": format_duration(eta_seconds),
                "by_stage_seconds": stage_estimates_s,
            },
        }
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ==========================================
# 🚀 ORCHESTRATION DU SCAN
# ==========================================

def run_scan(target: str, profile_key: str, mode_key: str, ollama_mode: str = "auto", ollama_url: Optional[str] = None):
    """Orchestration principale du scan"""
    scan_id = str(uuid.uuid4())[:8]

    current_stage = None
    stage_started_at = None

    # V2.5: Déterminer l'URL Ollama à utiliser
    try:
        base_url = get_ollama_base_url(ollama_mode=ollama_mode, ollama_url=ollama_url)
    except ValueError as e:
        add_log(f"❌ Erreur config Ollama: {e}", "error")
        scan_state["is_scanning"] = False
        scan_state["current_stage"] = "failed"
        mark_stage_terminal_state("failed")
        return
    
    profile = POWER_PROFILES.get(profile_key, POWER_PROFILES["balanced"])
    mode = SCAN_MODES.get(mode_key, SCAN_MODES["deep"])
    resolved_mode_key = MODE_CONTROLLER.resolve_mode_key(mode_key=mode_key, mode_config=mode)
    budget_plan = BUDGET_CONTROLLER.compute_plan(
        profile_key=profile_key,
        mode_key=resolved_mode_key,
        profile_config=profile,
        mode_config=mode,
        ollama_mode=ollama_mode,
    )

    scan_state.update({
        "id": scan_id,
        "is_scanning": True,
        "start_time": time.time(),
        "current_stage": "normalize",
        "stage_report": init_stage_report("normalize"),
        "progress": 0,
        "current_file": "",
        "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0, "skipped": 0},
        "logs": [],
        "vulnerabilities": [],
        "should_stop": False,
        "estimated_time": "Calcul...",
        "confidence_score": 0.0,
        "failed_analyses": 0,
        "successful_analyses": 0,
        "target_dir": None,
        "profile": profile_key,
        "mode": mode_key,
        "budget_info": {
            "max_files": mode["max_files"],
            "max_time_per_file": mode["max_time_per_file"],
            "min_severity": mode["min_severity"],
            "min_confidence": mode["min_confidence"],
            "llm_budget": budget_plan,
        },
        "preflight": {},
        "telemetry": init_scan_telemetry()
    })

    current_stage, stage_started_at = switch_scan_stage(current_stage, stage_started_at, "normalize")

    add_log("Nexus V3.0 Stable - scan session started", "info", stage="normalize", event="scan_start", scan_id=scan_id)
    add_log(
        f"🔗 Ollama: {ollama_mode} mode ({base_url})",
        "info",
        stage="normalize",
        event="ollama_endpoint",
        ollama_mode=ollama_mode,
        ollama_url=base_url,
    )
    add_log(
        f"📊 Profil: {profile['label']} | Mode: {mode['label']}",
        "info",
        stage="normalize",
        event="scan_profile_mode",
        profile=profile_key,
        mode=resolved_mode_key,
    )
    add_log(
        f"🎯 Budget: max {mode['max_files'] or '∞'} fichiers, sévérité ≥ {mode['min_severity']}",
        "info",
        stage="normalize",
        event="scan_budget",
        max_files=mode["max_files"],
        min_severity=mode["min_severity"],
        min_confidence=mode["min_confidence"],
    )
    add_log(
        f"🧮 LLM plan: ctx={budget_plan['max_context_tokens']} out={budget_plan['max_output_tokens']} "
        f"temp={budget_plan['temperature']} top_p={budget_plan['top_p']} retries={budget_plan['retries']} "
        f"timeout={budget_plan['timeout_s']}s passes={budget_plan['analysis_passes']} concurrency={budget_plan['concurrency']}",
        "info",
        stage="normalize",
        event="llm_budget_plan",
        llm_budget_plan=budget_plan,
    )
    add_log(
        f"🧭 Mode strategy: {resolved_mode_key}",
        "info",
        stage="normalize",
        event="mode_strategy",
        mode_strategy=resolved_mode_key,
    )
    add_log("Initialisation du scan...", "info", stage="normalize", event="scan_init")

    # V2.5: Vérification et installation automatique du modèle
    model_name = profile["model"]
    # V3.4: Logging now done inside ensure_model_available()
    if not ensure_model_available(model_name, base_url):  # V3.0: Passer URL dynamique
        add_log(f"❌ Impossible d'installer le modèle {model_name}. Scan annulé.", "critical")
        if current_stage:
            end_scan_stage(current_stage, stage_started_at)
            current_stage, stage_started_at = None, None
        scan_state["is_scanning"] = False
        scan_state["current_stage"] = "failed"
        mark_stage_terminal_state("failed")
        return

    tmp_dir = None
    target_dir = target
    
    try:
        # Clone si URL Git
        if target.startswith(("http", "git@")):
            # V3.0 FIX: Créer répertoire UNIQUE avec prefix
            tmp_dir = tempfile.mkdtemp(prefix="nexus_scan_")
            
            # V3.0 FIX: Vérifier qu'il est bien vide (sécurité)
            if os.path.exists(tmp_dir) and os.listdir(tmp_dir):
                import shutil
                add_log(f"⚠️ tmp_dir non-vide, nettoyage...", "warning")
                shutil.rmtree(tmp_dir)
                os.makedirs(tmp_dir)
            
            add_log(f"📥 Clonage du dépôt: {target}", "info")
            add_log(f"📂 Destination: {tmp_dir}", "info")
            Repo.clone_from(target, tmp_dir)
            target_dir = tmp_dir
            add_log(f"✅ Clone réussi", "info")
        
        scan_state["target_dir"] = target_dir

        current_stage, stage_started_at = switch_scan_stage(current_stage, stage_started_at, "index")
        
        telemetry = scan_state.setdefault("telemetry", init_scan_telemetry())
        collection = collect_scan_candidates(target_dir, resolved_mode_key, mode)
        file_entries = collection["file_entries"]
        discovered_count = collection["files_discovered"]
        telemetry["files_discovered"] = discovered_count
        telemetry["bytes_discovered"] = collection["bytes_discovered"]
        telemetry["bytes_scheduled"] = collection["bytes_scheduled"]
        telemetry["mode_strategy"] = resolved_mode_key
        telemetry["hotspot_files_discovered"] = sum(1 for entry in file_entries if entry.get("score", 0) > 0 and entry.get("reasons"))

        if collection["files_skipped"] > 0:
            skipped_count = collection["files_skipped"]
            max_files = mode["max_files"]
            add_log(
                f"✂️ Limite mode {mode_key}: {discovered_count} → {max_files} fichiers",
                "info",
                stage="index",
                event="file_limit_applied",
                discovered=discovered_count,
                scheduled=max_files,
                skipped=skipped_count,
            )
            scan_state["stats"]["skipped"] = skipped_count
        else:
            scan_state["stats"]["skipped"] = 0

        total_files = collection["files_scheduled"]
        telemetry["files_scheduled"] = total_files
        scan_state["stats"]["files"] = total_files
        scan_state["preflight"] = {
            "files_discovered": discovered_count,
            "files_scheduled": total_files,
            "files_skipped": scan_state["stats"]["skipped"],
            "bytes_scheduled": collection["bytes_scheduled"],
            "mode_strategy": resolved_mode_key,
        }

        add_log(
            f"📂 Index terminé: {total_files} fichier(s) planifié(s)",
            "info",
            stage="index",
            event="index_summary",
            files_discovered=discovered_count,
            files_scheduled=total_files,
        )
        
        if total_files == 0:
            add_log("⚠️ Aucun fichier correspondant aux critères.", "warning")
            scan_state["progress"] = 100
            scan_state["estimated_time"] = "Terminé"
            scan_state["current_stage"] = "completed"
            mark_stage_terminal_state("completed")
            return

        current_stage, stage_started_at = switch_scan_stage(current_stage, stage_started_at, "analyze")
        add_log(f"📁 {total_files} fichiers à analyser", "info", stage="analyze", event="analyze_start", files=total_files)

        engine = StableEngine(
            profile,
            mode,
            budget_plan=budget_plan,
            ollama_base_url=base_url,
            profile_name=profile_key,
        )
        start_ts = time.time()
        cross_file_hints: List[str] = []
        
        for i, file_entry in enumerate(file_entries):
            if scan_state["should_stop"]:
                add_log("🛑 Scan interrompu par l'utilisateur", "warning")
                break
            
            # Estimation temps restant
            elapsed = time.time() - start_ts
            if i > 0:
                avg_time = elapsed / i
                remain = avg_time * (total_files - i)
                scan_state["estimated_time"] = f"{int(remain)} sec"
            
            filepath = file_entry.get("path")
            filename = os.path.basename(filepath)
            hotspot_reasons = file_entry.get("reasons", [])
            
            # Timeout par fichier selon le mode
            file_start = time.time()
            vulns = engine.scan_file(
                filepath,
                filename,
                analysis_context={
                    "mode_key": resolved_mode_key,
                    "hotspot_reasons": hotspot_reasons,
                    "cross_file_hints": cross_file_hints if resolved_mode_key == "deep" else [],
                },
            )
            file_duration = time.time() - file_start
            telemetry["files_processed"] += 1
            add_log(
                f"🧾 Fichier analysé: {filename}",
                "info",
                stage="analyze",
                event="file_analyzed",
                filename=filename,
                duration_ms=round(file_duration * 1000, 2),
                findings=len(vulns),
                hotspot_reasons=hotspot_reasons,
            )

            if resolved_mode_key == "deep" and vulns:
                cross_file_hints = MODE_CONTROLLER.update_cross_file_hints(cross_file_hints, filename, vulns)
            
            max_time = mode["max_time_per_file"]
            if file_duration > max_time:
                add_log(f"⏱️ {filename}: {file_duration:.0f}s (budget: {max_time}s)", "warning")
            
            if vulns:
                for v in vulns:
                    v["id"] = len(scan_state["vulnerabilities"]) + 1
                    scan_state["vulnerabilities"].append(v)
                    
                    sev = v["severity"].lower()
                    if sev in scan_state["stats"]:
                        scan_state["stats"][sev] += 1
                    
                    if v["severity"] in ["Critical", "High"]:
                        add_log(f"🚨 {v['severity']}: {v['title']} ({filename})", "error")

            scan_state["progress"] = int(((i + 1) / total_files) * 100)

        current_stage, stage_started_at = switch_scan_stage(current_stage, stage_started_at, "correlate")
        
        # Calcul score de confiance global
        if scan_state["vulnerabilities"]:
            avg_conf = sum(v["confidence"] for v in scan_state["vulnerabilities"]) / len(scan_state["vulnerabilities"])
            scan_state["confidence_score"] = round(avg_conf, 2)
        
        if not scan_state["should_stop"]:
            total_time = time.time() - start_ts
            add_log(f"✅ Audit terminé en {total_time:.0f}s", "success")
            add_log(f"📊 Confiance globale: {scan_state['confidence_score']}%", "info")
            add_log(f"✅ Analyses réussies: {scan_state['successful_analyses']}", "success")
            if scan_state['failed_analyses'] > 0:
                add_log(f"❌ Analyses échouées: {scan_state['failed_analyses']}", "warning")
            
            current_stage, stage_started_at = switch_scan_stage(current_stage, stage_started_at, "report")
            scan_state["progress"] = 100
            scan_state["estimated_time"] = "Terminé"
            
            summary = {
                "id": scan_id,
                "date": datetime.now().isoformat(),
                "target": target,
                "profile": profile_key,
                "mode": mode_key,
                "stats": scan_state["stats"],
                "confidence_score": scan_state["confidence_score"],
                "duration_seconds": int(total_time),
                "successful_analyses": scan_state["successful_analyses"],
                "failed_analyses": scan_state["failed_analyses"],
                "llm_budget": {
                    "max_context_tokens": budget_plan.get("max_context_tokens"),
                    "max_output_tokens": budget_plan.get("max_output_tokens"),
                    "temperature": budget_plan.get("temperature"),
                    "top_p": budget_plan.get("top_p"),
                    "retries": budget_plan.get("retries"),
                    "analysis_passes": budget_plan.get("analysis_passes"),
                    "concurrency": budget_plan.get("concurrency"),
                },
                "telemetry": {
                    "stage_timings_ms": scan_state["telemetry"].get("stage_timings_ms", {}),
                    "llm_requests": scan_state["telemetry"].get("llm_requests", 0),
                    "chunks_total": scan_state["telemetry"].get("chunks_total", 0),
                    "tokens_estimated_total": scan_state["telemetry"].get("tokens_estimated_total", 0),
                }
            }
            save_to_history(summary)
            scan_state["current_stage"] = "completed"
            mark_stage_terminal_state("completed")
        else:
            scan_state["current_stage"] = "stopped"
            mark_stage_terminal_state("stopped")

    except Exception as e:
        add_log(f"🔥 Erreur Critique: {str(e)}", "critical", stage=scan_state.get("current_stage"), event="scan_error")
        scan_state["current_stage"] = "failed"
        mark_stage_terminal_state("failed")
    finally:
        if current_stage:
            end_scan_stage(current_stage, stage_started_at)
            current_stage, stage_started_at = None, None
        scan_state["is_scanning"] = False
        # V3.0: Cleanup tmp_dir si clone Git
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                import shutil
                shutil.rmtree(tmp_dir)
                add_log(f"🧹 Nettoyage du répertoire temporaire", "info")
            except Exception as e:
                print(f"[Cleanup] Erreur lors du nettoyage: {e}")

# ==========================================
# 📡 ENDPOINTS API
# ==========================================

@app.get("/")
async def root():
    return {"status": "ok", "version": "2.5-stable", "engine": "V2.2-based"}

@app.get("/profiles")
async def get_profiles():
    """Liste les profils de puissance disponibles"""
    return {k: {"label": v["label"], "description": v["description"]} 
            for k, v in POWER_PROFILES.items()}

@app.get("/modes")
async def get_modes():
    """Liste les modes de scan disponibles"""
    return {k: {"label": v["label"], "description": v["description"]} 
            for k, v in SCAN_MODES.items()}

@app.post("/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if scan_state["is_scanning"]:
        return {"success": False, "msg": "Scan en cours"}
    background_tasks.add_task(
        run_scan, 
        request.target, 
        request.profile, 
        request.mode,
        request.ollama_mode,  # V2.5: Mode de connexion Ollama
        request.ollama_url    # V2.5: URL custom si remote
    )
    return {"success": True, "msg": f"Scan lancé (profil: {request.profile}, mode: {request.mode})"}


@app.post("/scan/preflight")
async def scan_preflight(request: ScanRequest):
    try:
        preflight = build_scan_preflight(
            target=request.target,
            profile_key=request.profile,
            mode_key=request.mode,
            ollama_mode=request.ollama_mode,
            ollama_url=request.ollama_url,
        )
        scan_state["preflight"] = preflight
        add_log(
            "📐 Preflight calculé",
            "info",
            stage="normalize",
            event="preflight_ready",
            files=preflight.get("files", {}),
            eta=preflight.get("eta", {}),
            mode=preflight.get("mode"),
            profile=preflight.get("profile"),
        )
        return {"success": True, "preflight": preflight}
    except Exception as e:
        add_log(
            f"⚠️ Preflight impossible: {str(e)[:200]}",
            "warning",
            stage="normalize",
            event="preflight_error",
        )
        return {"success": False, "message": f"Preflight impossible: {str(e)[:200]}"}

@app.post("/ollama/test")
async def test_ollama(request: dict):
    """Teste la connexion à un serveur Ollama et liste les modèles"""
    url = request.get("url", "").strip()
    
    if not url:
        return {"ok": False, "message": "URL manquante"}
    
    try:
        base_url = normalize_ollama_url(url)
        test_url = f"{base_url}/api/tags"
        
        response = requests.get(test_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            models = [m.get("name", "unknown") for m in data.get("models", [])][:10]  # Max 10 modèles
            return {
                "ok": True,
                "message": f"Connexion OK ({len(models)} modèles disponibles)",
                "models": models,
                "url": base_url
            }
        else:
            return {"ok": False, "message": f"HTTP {response.status_code}"}
    
    except requests.exceptions.Timeout:
        return {"ok": False, "message": "Timeout (5s) - Serveur inaccessible"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": "Erreur de connexion - vérifier l'URL et le port"}
    except ValueError as e:
        return {"ok": False, "message": str(e)}
    except Exception as e:
        return {"ok": False, "message": f"Erreur: {str(e)[:100]}"}


@app.post("/scan/stop")
async def stop_scan():
    """Arrête le scan en cours"""
    scan_state["should_stop"] = True
    scan_state["is_scanning"] = False
    scan_state["current_stage"] = "stopped"
    mark_stage_terminal_state("stopped")
    add_log("🛑 Arrêt demandé par l'utilisateur", "warning")
    return {"success": True, "message": "Scan stopping..."}

@app.get("/scan/stages")
async def get_scan_stages():
    return scan_state.get("stage_report", init_stage_report(scan_state.get("current_stage", "idle")))

@app.get("/scan/status")
async def get_status():
    if "stage_report" not in scan_state:
        scan_state["stage_report"] = init_stage_report(scan_state.get("current_stage", "idle"))
    return scan_state

@app.get("/history")
async def get_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []

@app.get("/export/json")
async def export_json():
    return scan_state["vulnerabilities"]

@app.post("/fix/generate")
async def generate_fix(request: FixRequest):
    vuln = next((v for v in scan_state["vulnerabilities"] if v["id"] == request.vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnérabilité non trouvée")
    
    result = generate_fix_patch(vuln)
    return result

@app.get("/fix/download/{patch_file}")
async def download_patch(patch_file: str):
    patch_path = os.path.join(PATCHES_DIR, patch_file)
    if not os.path.exists(patch_path):
        raise HTTPException(status_code=404, detail="Patch non trouvé")
    return FileResponse(patch_path, media_type='text/plain', filename=patch_file)

@app.get("/export/report")
async def export_report_html():
    """Génère un rapport HTML"""
    vulns_html = ""
    for v in scan_state["vulnerabilities"]:
        color = "red" if v['severity'] == 'Critical' else "orange" if v['severity'] == 'High' else "blue"
        conf_color = "green" if v['confidence'] >= 70 else "orange" if v['confidence'] >= 40 else "red"
        
        vulns_html += f"""
        <div class="vuln-card {v['severity']}">
            <h3>
                <span class="badge {color}">{v['severity']}</span> 
                {v['title']}
                <span class="confidence {conf_color}">Confiance: {v['confidence']}%</span>
            </h3>
            <div class="meta">Fichier: <strong>{v['file']}</strong> | Ligne: {v['line'] or 'N/A'}</div>
            <p>{v['description']}</p>
            <div class="code-block"><pre>{v['snippet']}</pre></div>
            <div class="fix-block"><strong>Correction:</strong><pre>{v['fix']}</pre></div>
        </div>
        """
        
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Nexus Auditor V3.0 Report - {datetime.now().strftime('%Y-%m-%d')}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px; color: #333; }}
            h1 {{ border-bottom: 2px solid #6366f1; padding-bottom: 10px; }}
            .header {{ display: flex; justify-content: space-between; margin-bottom: 40px; }}
            .vuln-card {{ border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .vuln-card.Critical {{ border-left: 5px solid #ef4444; }}
            .vuln-card.High {{ border-left: 5px solid #f97316; }}
            .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
            .badge.red {{ background-color: #ef4444; }} 
            .badge.orange {{ background-color: #f97316; }} 
            .badge.blue {{ background-color: #3b82f6; }}
            .confidence {{ float: right; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
            .confidence.green {{ background-color: #10b981; color: white; }}
            .confidence.orange {{ background-color: #f97316; color: white; }}
            .confidence.red {{ background-color: #ef4444; color: white; }}
            .code-block {{ background: #f1f5f9; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; margin: 10px 0; }}
            .fix-block {{ background: #ecfdf5; padding: 10px; border-radius: 4px; font-family: monospace; color: #065f46; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🛡️ Nexus Auditor V3.0 Stable Report</h1>
                <p>Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
                <p>Scan ID: {scan_state.get('id', 'N/A')}</p>
                <p>Profil: {scan_state.get('profile', 'N/A')} | Mode: {scan_state.get('mode', 'N/A')}</p>
            </div>
            <div style="text-align: right;">
                <p><strong>Critical:</strong> {scan_state['stats']['critical']}</p>
                <p><strong>High:</strong> {scan_state['stats']['high']}</p>
                <p><strong>Confiance:</strong> {scan_state['confidence_score']}%</p>
            </div>
        </div>
        
        <h2>Vulnérabilités Détectées</h2>
        {vulns_html if vulns_html else "<p>Aucune vulnérabilité détectée.</p>"}
    </body>
    </html>
    """
    return HTMLResponse(content=html)

# ==========================================
# 🚀 MAIN
# ==========================================

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🛡️ Nexus Auditor V3.0 Stable")
    print("=" * 60)
    print("✨ Basé sur V2.2 (moteur stable)")
    print("✨ Prompt IA strict anti-hallucination")
    print("✨ Profils de puissance: eco, balanced, elite, titan")
    print("✨ Modes de scan: rapid, deep, devsecops")
    print("✨ Filtrage POST-IA selon le mode")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
