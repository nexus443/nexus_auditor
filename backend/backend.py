import os
import sys
import json
import re
import requests
import shutil
import tempfile
import time
import uuid
import difflib
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from git import Repo

# ==========================================
# 🧠 OLLAMA AUTO-DETECTION SYSTEM
# ==========================================

OLLAMA_TIMEOUT = 2  # seconds for connectivity test
OLLAMA_RETRIES = 2  # retry attempts per URL


def is_running_in_docker() -> bool:
    """Détecte si le code tourne dans un container Docker."""
    # Méthode 1 : fichier .dockerenv
    if os.path.exists("/.dockerenv"):
        return True
    
    # Méthode 2 : cgroup (Linux)
    try:
        with open("/proc/1/cgroup", "rt") as f:
            content = f.read()
            return "docker" in content or "containerd" in content
    except Exception:
        pass
    
    # Méthode 3 : Windows - vérifier si on est dans un réseau Docker
    # (moins fiable mais peut aider)
    return False


def test_ollama(url: str) -> bool:
    """Test si Ollama est accessible à l'URL donnée."""
    try:
        r = requests.post(
            url,
            json={
                "model": "llama3",  # model minimal pour test
                "prompt": "ping",
                "stream": False
            },
            timeout=OLLAMA_TIMEOUT
        )
        return r.status_code == 200
    except Exception:
        return False


def resolve_ollama_url() -> tuple[str, str]:
    """
    Résout automatiquement l'URL Ollama optimale.
    Retourne: (url, environment_type)
    """
    # 1️⃣ Variable d'environnement (priorité absolue)
    env_url = os.getenv("OLLAMA_URL")
    if env_url:
        print(f"[Ollama] 🎯 Using env OLLAMA_URL: {env_url}")
        return (env_url, "env_override")
    
    candidates = []
    env_type = "unknown"
    
    # 2️⃣ Détection Docker
    in_docker = is_running_in_docker()
    
    if in_docker:
        print("[Ollama] 🐳 Docker environment detected")
        env_type = "docker"
        candidates.extend([
            "http://host.docker.internal:11434/api/generate",  # Docker Desktop
            "http://ollama:11434/api/generate",  # Docker Compose service
            "http://172.17.0.1:11434/api/generate",  # Docker bridge network
        ])
    else:
        print("[Ollama] 💻 Native environment detected")
        env_type = "native"
        candidates.extend([
            "http://127.0.0.1:11434/api/generate",
            "http://localhost:11434/api/generate",
        ])
    
    # 3️⃣ Fallback croisé (au cas où détection Docker échoue)
    candidates.extend([
        "http://localhost:11434/api/generate",
        "http://host.docker.internal:11434/api/generate",
    ])
    
    # 4️⃣ Test de connectivité avec retry
    print(f"[Ollama] 🔍 Testing {len(candidates)} candidate URLs...")
    for url in candidates:
        for attempt in range(OLLAMA_RETRIES):
            if test_ollama(url):
                print(f"[Ollama] ✅ Connected → {url}")
                return (url, env_type)
            if attempt < OLLAMA_RETRIES - 1:
                time.sleep(0.3)
    
    # 5️⃣ Échec - erreur claire
    raise RuntimeError(
        "❌ Impossible de joindre Ollama automatiquement.\n"
        "➡️ Solutions:\n"
        "   1. Démarrez Ollama: 'ollama serve'\n"
        "   2. Ou définissez: OLLAMA_URL=http://your-ollama-url:11434/api/generate"
    )


# Auto-détection au démarrage
print("\n" + "="*60)
print("🚀 Nexus Auditor V3.3 Ultimate - Initializing...")
print("="*60)

try:
    OLLAMA_URL, ENVIRONMENT_TYPE = resolve_ollama_url()
    print(f"[Ollama] Environment: {ENVIRONMENT_TYPE}")
except RuntimeError as e:
    print(f"\n⚠️  WARNING: {e}\n")
    # Fallback par défaut (ne fonctionnera probablement pas mais permet au moins de démarrer)
    OLLAMA_URL = "http://localhost:11434/api/generate"
    ENVIRONMENT_TYPE = "fallback"

# ==========================================
# ⚙️ CONFIGURATION & PROFILS
# ==========================================
HISTORY_FILE = "audit_history.json"
RAW_RESPONSES_DIR = "./audit_logs/raw_responses"
PATCHES_DIR = "./audit_logs/patches"
TIMEOUT_DEFAULT = 300

os.makedirs(RAW_RESPONSES_DIR, exist_ok=True)
os.makedirs(PATCHES_DIR, exist_ok=True)

# 🔥 NOUVEAUTÉ : Limites GPU par profil
GPU_LIMITS = {
    "eco": 1,        # 1 seul appel IA simultané (Mac M1, GPU faible)
    "balanced": 2,   # 2 appels IA max (RTX 3060, RTX 4060)
    "elite": 4,      # 4 appels IA max (RTX 3090, 4090)
    "titan": 6       # 6 appels IA max (RTX 5090)
}

# 🧠 Semaphore global pour contrôler les appels GPU
gpu_semaphore = None

SOFT_TERMS = [
    "peut-être", "potentiellement", "il semble", "probablement",
    "peut être", "possiblement", "éventuellement", "peut-etre",
    "maybe", "potentially", "seems", "probably", "possibly"
]

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
    "cpp": ["XSS"],
    "c": ["XSS"],
    "rs": ["XSS"],
}

# ==========================================
# 🧠 MODEL EXECUTION PROFILES
# ==========================================
# Caractéristiques d'exécution par modèle (indépendant des profils utilisateur)
# 🔒 Configuration CONSERVATRICE pour stabilité maximale

MODEL_PROFILES = {
    "deepseek-coder:6.7b": {
        "max_parallel": 1,  # ⚡ SÉQUENTIEL OBLIGATOIRE (modèle très lent)
        "timeout_per_file": 240,  # 4 minutes par fichier (conservateur)
        "latency": "high",
        "eco_mode": True,
        "description": "Modèle lourd - stable mais lent. Optimisé pour CPU/GPU faibles."
    },
    "qwen2.5-coder:14b": {
        "max_parallel": 1,  # 🔒 SÉQUENTIEL aussi (RTX 3060 = mono-file pour stabilité)
        "timeout_per_file": 180,  # 3 minutes par fichier
        "latency": "medium",
        "eco_mode": False,
        "description": "Équilibré - séquentiel pour éviter surcharge GPU moyenne"
    },
    "qwen2.5-coder:32b": {
        "max_parallel": 2,  # 🔒 Parallélisme RÉDUIT (seulement 2 au lieu de 4)
        "timeout_per_file": 150,  # 2.5 minutes (augmenté)
        "latency": "low",
        "eco_mode": False,
        "description": "Haute performance - nécessite RTX 3090+ pour parallélisme"
    },
    # Fallback par défaut pour modèles inconnus
    "_default": {
        "max_parallel": 1,  # 🔒 CONSERVATEUR par défaut
        "timeout_per_file": 180,
        "latency": "medium",
        "eco_mode": False,
        "description": "Configuration standard conservatrice"
    }
}

# ⚡ Profils optimisés avec timeout intelligent
PROFILES = {
    "eco": {
        "label": "Eco (Optimisé Stabilité)",
        "color": "green",
        "model": "deepseek-coder:6.7b",
        "ctx": 8192,
        "chunk_size": 4000,
        "read_full_file": False,
        # � Note: timeout et parallel_files définis dans MODEL_PROFILES
        "prompt_template": """
        ROLE: Security Auditor. TARGET: Find CRITICAL vulnerabilities only (OWASP Top 10).
        FORMAT: JSON Only. No markdown.
        CODE ({filename}): ```{content}```
        RESPONSE: [{{"title": "Type", "severity": "Critical|High|Medium|Low", "line": 10, "description": "Technical proof", "fix": "Secure code", "type": "SQLi|XSS|RCE", "confidence": 85, "reasoning": {{"pattern": "attack pattern", "cve_refs": [], "exploit_example": "optional"}}}}]
        """
    },
    "balanced": {
        "label": "Standard (Recommandé - GPU moyenne)",
        "color": "orange",
        "model": "qwen2.5-coder:14b",
        "ctx": 16384,
        "chunk_size": 12000,
        "read_full_file": False,
        # 📝 Note: timeout et parallel_files définis dans MODEL_PROFILES
        "prompt_template": """
        Role: Senior SAST Auditor with AI Profiling.
        Task: Analyze code for SECURITY VULNERABILITIES (OWASP A1-A10).
        Context: Ignore style/comments. Focus on RCE, SQLi, XSS, Auth Bypass.
        IMPORTANT: For each vulnerability, explain WHY (pattern, CVEs, exploit).
        Code ({filename}): ```{content}```
        Output JSON: [{{"title": "Vuln Name", "severity": "Critical|High|Medium|Low", "line": <int>, "description": "Technical proof", "fix": "Secure code", "type": "vuln type", "confidence": 0-100, "reasoning": {{"pattern": "SQL concat / memcpy overflow", "cve_refs": ["CVE-2021-1234"], "exploit_example": "how attacker exploits"}}}}]
        """
    },
    "elite": {
        "label": "Elite (Haute Performance - RTX 3090/4090)",
        "color": "red",
        "model": "qwen2.5-coder:32b",
        "ctx": 32768,
        "chunk_size": 24000,
        "read_full_file": False,
        # 📝 Note: timeout et parallel_files définis dans MODEL_PROFILES
        "prompt_template": """
        Role: Lead Security Researcher with Deep Profiling.
        Task: Deep semantic analysis for LOGICAL and SECURITY vulnerabilities.
        Instructions: 
        1. Trace data flow, find unvalidated inputs
        2. For EACH vulnerability, provide detailed reasoning:
           - Pattern type (buffer overflow, SQL injection, XSS)
           - Reference similar CVEs
           - Explain exploit scenario step-by-step
        3. Provide CVE references when patterns match known vulnerabilities
        Code ({filename}): ```{content}```
        JSON Output: [{{"title": "...", "severity": "Critical|High|Medium|Low", "line": <int>, "description": "Detailed analysis", "fix": "Secure code", "type": "vuln type", "confidence": 0-100, "cve_reference": "CVE-XXXX-XXXX", "reasoning": {{"pattern": "specific pattern like 'memcpy() without bounds check'", "cve_refs": ["CVE-2021-3156", "CVE-2019-1234"], "exploit_example": "Attacker could inject shell commands via..."}}}}]
        """
    },
    "titan": {
        "label": "🔥 Titan (RTX 5090 - Full Power)",
        "color": "purple",
        "model": "qwen2.5-coder:32b",
        "ctx": 131072,
        "chunk_size": 100000,
        "read_full_file": True,
        # 📝 Note: timeout et parallel_files définis dans MODEL_PROFILES
        "prompt_template": """
        ROLE: Elite AI Security Research Team - Multi-Layer Analysis
        CONTEXT: You have access to the COMPLETE file content. Perform exhaustive analysis.
        CAPABILITIES: 128k context window, deep semantic understanding, multi-pass analysis
        
        ANALYSIS METHODOLOGY:
        1. STATIC ANALYSIS LAYER:
           - Parse code structure, identify all entry points
           - Map data flow from user input to sensitive operations
           - Detect patterns matching OWASP Top 10 + SANS 25 + MITRE ATT&CK
        
        2. SEMANTIC ANALYSIS LAYER:
           - Understand business logic vulnerabilities
           - Identify race conditions, TOCTOU issues
           - Detect authentication/authorization bypasses
           - Find cryptographic weaknesses
        
        3. EXPLOIT CHAIN ANALYSIS:
           - Combine minor issues into exploit chains
           - Identify privilege escalation paths
           - Map attack surfaces
        
        4. CVE CORRELATION:
           - Match patterns to known CVEs (2019-2024)
           - Reference CWE (Common Weakness Enumeration)
           - Link to real-world exploits when applicable
        
        CODE ANALYSIS ({filename}) - FULL FILE CONTENT:
        ```
        {content}
        ```
        
        OUTPUT FORMAT - Comprehensive JSON Array:
        [
          {{
            "id": <sequential>,
            "title": "Precise vulnerability name",
            "severity": "Critical|High|Medium|Low",
            "line": <exact line number>,
            "description": "Multi-paragraph technical analysis with code references, variable names, and exploitation path",
            "fix": "Production-ready secure code with inline comments explaining the fix",
            "type": "Precise category (e.g., 'SQL Injection - Time-Based Blind', 'XSS - Stored - DOM-Based')",
            "confidence": 0-100,
            "cve_reference": "Primary CVE if pattern matches",
            "cwe_id": "CWE-XXX",
            "reasoning": {{
              "pattern": "Exact technical pattern detected",
              "cve_refs": ["CVE-2023-1234", "CVE-2022-5678"],
              "cwe_refs": ["CWE-89", "CWE-20"],
              "exploit_example": "Step-by-step exploit",
              "mitigation_priority": "Critical|High|Medium|Low",
              "business_impact": "Precise impact",
              "attack_vector": "Network|Adjacent|Local|Physical",
              "complexity": "Low|High"
            }},
            "related_vulns": [<IDs of related vulnerabilities>],
            "exploit_chain": "Optional: How this combines with other vulns"
          }}
        ]
        
        STRICT REQUIREMENTS:
        - NO false positives: Every vulnerability must have concrete proof
        - NO generic descriptions: Reference actual variable names, line numbers
        - NO "potential" or "possible": Only confirmed vulnerabilities
        - PRIORITIZE: Critical > High > Medium > Low
        - DEPTH: For Critical/High, provide multi-paragraph analysis
        """
    }
}

# ==========================================
# 🎯 SCAN MODES (Semantic Analysis Depth)
# ==========================================
# Modes control WHAT and HOW DEEPLY to analyze, NOT performance
# Performance is ONLY controlled by PROFILES

SCAN_MODES = {
    "rapid": {
        "label": "⚡ Scan Rapide",
        "description": "Focus on critical, exploitable vulnerabilities only",
        "file_extensions": ('.py', '.js', '.ts', '.php', '.java', '.go'),
        "severity_focus": ["Critical", "High"],
        "max_vulns_per_file": 3,
        "analysis_depth": "surface",
        "prompt_modifier": """

🎯 RAPID SCAN MODE - CRITICAL ONLY:
- Report ONLY Critical or High severity vulnerabilities
- Ignore theoretical or edge-case issues
- Focus on obvious, immediately exploitable patterns
- No speculation - confirmed vulnerabilities only
- MAX 3 findings per file (most critical)
"""
    },
    "deep": {
        "label": "🧠 Scan Profond",
        "description": "Balanced analysis with detailed reasoning",
        "file_extensions": ('.py', '.js', '.jsx', '.ts', '.tsx', '.php', 
                          '.java', '.c', '.cpp', '.rs', '.go', '.sql', 
                          '.yaml', '.xml'),
        "severity_focus": ["Critical", "High", "Medium"],
        "max_vulns_per_file": 6,
        "analysis_depth": "standard",
        "prompt_modifier": """

🧠 DEEP SCAN MODE - COMPREHENSIVE:
- Report Critical, High, and Medium severity vulnerabilities
- Include detailed attack vectors and exploitation paths
- Explain the reasoning behind each finding
- Medium severity if genuinely exploitable
- MAX 6 findings per file
"""
    },
    "devsecops": {
        "label": "🔐 Scan DevSecOps",
        "description": "Exhaustive production-grade security audit",
        "file_extensions": ('.yaml', '.yml', '.json', '.env', '.toml', 
                          'Dockerfile', 'docker-compose.yml',
                          '.py', '.js', '.ts', '.go', '.java', '.php'),
        "severity_focus": ["Critical", "High", "Medium", "Low"],
        "max_vulns_per_file": 12,
        "analysis_depth": "exhaustive",
        "prompt_modifier": """

🔐 DEVSECOPS MODE - EXHAUSTIVE:
- Report ALL severity levels (Critical, High, Medium, Low)
- Include infrastructure, configuration, and secrets issues
- Map findings to CWE / OWASP / MITRE ATT&CK when applicable
- Identify exploit chains and privilege escalation paths
- Check for CI/CD security misconfigurations
- Production readiness assessment
- NO strict limit if critical issues found
"""
    }
}

app = FastAPI(title="Nexus Auditor Enterprise API V2.4 - GPU Intelligent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 📊 ÉTAT & HISTORIQUE
# ==========================================

scan_state = {
    "id": None,
    "is_scanning": False,
    "start_time": None,
    "progress": 0,
    "current_file": "",
    "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0},
    "logs": [],
    "vulnerabilities": [],
    "should_stop": False,
    "estimated_time": "Calcul...",
    "confidence_score": 0.0,
    "failed_analyses": 0,
    "successful_analyses": 0,
    "target_dir": None,
    "parallel_active": 0,
    "gpu_queue": 0,  # 🔥 NOUVEAUTÉ : Files d'attente GPU
    "ollama_url": OLLAMA_URL,  # 🧠 Auto-détecté
    "environment": ENVIRONMENT_TYPE  # docker / native / env_override
}

class ScanRequest(BaseModel):
    target: str
    profile: str = "balanced"
    mode: str = "deep"

class FixRequest(BaseModel):
    vuln_id: int

# ==========================================
# 🛠️ UTILITAIRES
# ==========================================

def add_log(msg, type="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{type.upper()}] {msg}")
    if len(scan_state["logs"]) > 500: 
        scan_state["logs"].pop(0)
    scan_state["logs"].append({"msg": msg, "type": type, "time": ts})

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

def extract_json_from_text(text: str) -> Any:
    try:
        return json.loads(text)
    except:
        pass
    
    patterns = [
        r'\[\s*\{.*\}\s*\]',
        r'\{.*\}',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                continue
    
    json_block = re.search(r'```json\s*(\[.*?\]|\{.*?\})\s*```', text, re.DOTALL)
    if json_block:
        try:
            return json.loads(json_block.group(1))
        except:
            pass
    
    return None

def calculate_confidence(vuln: dict, raw_response: str, filepath: str) -> float:
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
                add_log(f"⚠️ Incohérence détectée : {blocked} dans {file_ext}", "warning")
    
    return max(0, min(100, score))

def normalize_vulnerability(vuln: dict, filepath: str, filename: str, raw_response: str) -> dict:
    line = vuln.get("line", "0")
    line_clean = ''.join(filter(str.isdigit, str(line)))
    if not line_clean:
        line_clean = "0"
    
    snippet = vuln.get("snippet", "")
    if not snippet and line_clean != "0":
        snippet = extract_code_context(filepath, line_clean)
    
    sev = str(vuln.get("severity", "Low")).capitalize()
    if "crit" in sev.lower():
        sev = "Critical"
    elif "high" in sev.lower():
        sev = "High"
    elif "med" in sev.lower():
        sev = "Medium"
    elif "low" in sev.lower():
        sev = "Low"
    else:
        sev = "Low"
    
    confidence = calculate_confidence(vuln, raw_response, filepath)
    
    reasoning = vuln.get("reasoning", {})
    if not isinstance(reasoning, dict):
        reasoning = {}
    
    normalized = {
        "file": filename,
        "filepath": filepath,
        "title": vuln.get("title", "Vulnérabilité Inconnue"),
        "severity": sev,
        "line": int(line_clean) if line_clean != "0" else None,
        "description": vuln.get("description", "Pas de description fournie."),
        "fix": vuln.get("fix", "Pas de correctif proposé."),
        "confidence": round(confidence, 2),
        "snippet": snippet if snippet else "Code non disponible",
        "type": vuln.get("type", "Unknown"),
        "cve_reference": vuln.get("cve_reference", None),
        "cwe_id": vuln.get("cwe_id", None),
        "reasoning": {
            "pattern": reasoning.get("pattern", "Non spécifié"),
            "cve_refs": reasoning.get("cve_refs", []),
            "cwe_refs": reasoning.get("cwe_refs", []),
            "exploit_example": reasoning.get("exploit_example", "Non fourni"),
            "business_impact": reasoning.get("business_impact", "Non évalué"),
            "attack_vector": reasoning.get("attack_vector", "Unknown"),
            "mitigation_priority": reasoning.get("mitigation_priority", sev)
        },
        "timestamp": datetime.now().isoformat()
    }
    
    return normalized

# ==========================================
# 🔧 AUTO-FIX ENGINE
# ==========================================

def generate_fix_patch(vuln: dict) -> Optional[dict]:
    """Génère un patch de correctif pour une vulnérabilité."""
    try:
        # Essayer d'obtenir le filepath depuis la vulnérabilité
        filepath = vuln.get("filepath")
        filename = vuln.get("file", "unknown")
        
        # Si pas de filepath ou fichier inexistant, chercher dans target_dir
        if not filepath or not os.path.exists(filepath):
            add_log(f"⚠️ Filepath manquant ou invalide pour {filename}, recherche...", "warning")
            
            target_dir = scan_state.get("target_dir")
            if target_dir and os.path.exists(target_dir):
                # Chercher le fichier dans l'arborescence
                for root, dirs, files in os.walk(target_dir):
                    if filename in files:
                        filepath = os.path.join(root, filename)
                        add_log(f"✅ Fichier trouvé: {filepath}", "info")
                        break
        
        # Vérification finale
        if not filepath:
            error_msg = f"Impossible de localiser le fichier: {filename}"
            add_log(f"❌ {error_msg}", "error")
            return {
                "success": False,
                "error": "Fichier introuvable - le contexte du scan n'est plus disponible. Relancez l'audit pour corriger cette faille."
            }
        
        if not os.path.exists(filepath):
            error_msg = f"Le fichier n'existe plus: {filepath}"
            add_log(f"❌ {error_msg}", "error")
            return {
                "success": False,
                "error": error_msg
            }
        
        # Récupérer les infos de correctif
        line = vuln.get("line")
        fix_code = vuln.get("fix", "")
        
        if not line or not fix_code:
            return {"success": False, "error": "Informations de correctif insuffisantes"}
        
        # Lire le fichier original
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_lines = f.readlines()
        
        modified_lines = original_lines.copy()
        vuln_line_idx = line - 1
        
        if vuln_line_idx < 0 or vuln_line_idx >= len(original_lines):
            return {"success": False, "error": f"Numéro de ligne invalide: {line}"}
        
        # Préparer le correctif avec indentation
        fix_lines = fix_code.strip().split('\n')
        indent = len(original_lines[vuln_line_idx]) - len(original_lines[vuln_line_idx].lstrip())
        indent_str = ' ' * indent
        
        fixed_lines = [indent_str + line.lstrip() + '\n' if not line.endswith('\n') else indent_str + line.lstrip() for line in fix_lines]
        modified_lines[vuln_line_idx:vuln_line_idx+1] = fixed_lines
        
        # Générer le diff
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{vuln['file']}",
            tofile=f"b/{vuln['file']}",
            lineterm=''
        )
        
        diff_text = '\n'.join(diff)
        
        # Sauvegarder le patch
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        patch_filename = f"patch_{vuln['id']}_{timestamp}.patch"
        patch_path = os.path.join(PATCHES_DIR, patch_filename)
        
        with open(patch_path, 'w', encoding='utf-8') as f:
            f.write(diff_text)
        
        add_log(f"✅ Patch sauvegardé: {patch_filename}", "success")
        
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
# 🧠 MOTEUR PARALLÈLE GPU-OPTIMISÉ V2
# ==========================================

class IntelligentGPUEngine:
    def __init__(self, config, scan_mode="deep"):
        self.config = config
        self.scan_mode = SCAN_MODES.get(scan_mode, SCAN_MODES["deep"])
        self.fallback_model = "deepseek-coder:6.7b"

    def call_ollama_with_retry(self, prompt: str, filename: str, max_retries=3) -> Optional[dict]:
        """🔥 NOUVEAUTÉ : Timeout intelligent + Semaphore GPU"""
        
        # 🧠 Récupération timeout depuis MODEL_PROFILES (adapté au modèle)
        model = self.config["model"]
        model_profile = MODEL_PROFILES.get(model, MODEL_PROFILES["_default"])
        base_timeout = model_profile["timeout_per_file"]
        
        # 🔥 Timeout adaptatif : +10s par 10k caractères
        content_adjustment = int(len(prompt) / 10000) * 10
        intelligent_timeout = base_timeout + content_adjustment
        
        for attempt in range(max_retries):
            try:
                # 🔥 NOUVEAU : Acquisition du semaphore GPU AVANT l'appel
                scan_state["gpu_queue"] += 1
                add_log(f"🎯 [{filename}] File GPU: {scan_state['gpu_queue']}", "info")
                
                with gpu_semaphore:  # 🔥 Contrôle GPU global
                    scan_state["gpu_queue"] -= 1
                    scan_state["parallel_active"] += 1
                    
                    add_log(f"🤖 [{filename}] GPU slot acquis (active: {scan_state['parallel_active']})", "info")
                    
                    backoff = 2 ** attempt
                    if attempt > 0:
                        time.sleep(backoff)
                    
                    response = requests.post(
                        OLLAMA_URL,
                        json={
                            "model": model,
                            "prompt": prompt,
                            "stream": False,
                            "format": "json",
                            "options": {
                                "temperature": 0.1, 
                                "num_ctx": self.config["ctx"],
                                "num_gpu": 1,
                                "num_thread": 8
                            }
                        },
                        timeout=intelligent_timeout
                    )
                    
                    scan_state["parallel_active"] -= 1
                    
                    if response.status_code == 200:
                        raw_text = response.json().get('response', '{}')
                        save_raw_response(filename, raw_text)
                        
                        parsed = extract_json_from_text(raw_text)
                        
                        if parsed is not None:
                            add_log(f"✅ [{filename}] Réponse valide ({len(str(parsed))} chars)", "success")
                            return {"data": parsed, "raw": raw_text}
                        else:
                            add_log(f"⚠️ [{filename}] JSON invalide (tentative {attempt+1})", "warning")
                            continue
                    else:
                        add_log(f"❌ [{filename}] HTTP {response.status_code}", "error")
                        
            except requests.exceptions.Timeout:
                add_log(f"⏱️ [{filename}] Timeout après {intelligent_timeout}s", "warning")
                scan_state["parallel_active"] = max(0, scan_state["parallel_active"] - 1)
            except Exception as e:
                add_log(f"❌ [{filename}] Erreur: {str(e)}", "error")
                scan_state["parallel_active"] = max(0, scan_state["parallel_active"] - 1)
        
        # Fallback si tous les retries échouent
        if model != self.fallback_model and max_retries > 0:
            add_log(f"🔄 [{filename}] Fallback vers {self.fallback_model}", "info")
            old_model = self.config["model"]
            self.config["model"] = self.fallback_model
            result = self.call_ollama_with_retry(prompt, filename, max_retries=1)
            self.config["model"] = old_model
            return result
        
        return None

    def scan_file(self, filepath, filename):
        """Scan un fichier - mode parallèle ou chunked selon config"""
        if scan_state["should_stop"]: 
            return []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip(): 
                return []
            
            # Mode Titan : lire fichier entier si < chunk_size
            if self.config.get("read_full_file", False) and len(content) < self.config["chunk_size"]:
                add_log(f"📄 [{filename}] Mode fichier entier ({len(content)} chars)", "info")
                # Inject semantic scan mode modifier
                base_prompt = self.config["prompt_template"]
                mode_modifier = self.scan_mode["prompt_modifier"]
                combined_prompt = f"{base_prompt}\n{mode_modifier}"
                prompt = combined_prompt.format(filename=filename, content=content)
                result = self.call_ollama_with_retry(prompt, filename)
                
                if result:
                    return self._process_result(result, filepath, filename)
                else:
                    scan_state["failed_analyses"] += 1
                    return []
            
            # Mode chunked pour gros fichiers
            chunks = []
            start = 0
            sz = self.config["chunk_size"]
            while start < len(content):
                chunks.append(content[start:start + sz])
                start += sz - 500

            all_vulns = []
            
            for i, chunk in enumerate(chunks):
                if scan_state["should_stop"]: 
                    break
                
                scan_state["current_file"] = f"{filename} ({i+1}/{len(chunks)})"
                # Inject semantic scan mode modifier
                base_prompt = self.config["prompt_template"]
                mode_modifier = self.scan_mode["prompt_modifier"]
                combined_prompt = f"{base_prompt}\n{mode_modifier}"
                prompt = combined_prompt.format(filename=filename, content=chunk)
                result = self.call_ollama_with_retry(prompt, filename)
                
                if result:
                    vulns = self._process_result(result, filepath, filename)
                    all_vulns.extend(vulns)
                    scan_state["successful_analyses"] += 1
                else:
                    scan_state["failed_analyses"] += 1
            
            return all_vulns

        except Exception as e:
            add_log(f"❌ Erreur analyse {filename}: {e}", "error")
            scan_state["failed_analyses"] += 1
            return []

    def _process_result(self, result, filepath, filename):
        """Traite le résultat JSON de l'IA + filtres sémantiques du mode de scan"""
        data = result["data"]
        raw_response = result["raw"]
        
        if isinstance(data, dict): 
            data = [data]
        
        vulns = []
        if isinstance(data, list):
            for v in data:
                normalized = normalize_vulnerability(v, filepath, filename, raw_response)
                
                # Filtre par sévérité selon le mode de scan
                if normalized["severity"] not in self.scan_mode["severity_focus"]:
                    add_log(f"🗑️ [{filename}] {normalized['severity']} filtered (mode: {self.scan_mode['label']})", "info")
                    continue
                
                if normalized["confidence"] < 20:
                    add_log(f"🗑️ [{filename}] Low confidence ({normalized['confidence']}%)", "warning")
                    continue
                
                vulns.append(normalized)
        
        # Limiter le nombre de findings selon le mode (tri par confiance)
        max_vulns = self.scan_mode["max_vulns_per_file"]
        if len(vulns) > max_vulns:
            vulns = sorted(vulns, key=lambda v: v["confidence"], reverse=True)
            original_count = len(vulns)
            vulns = vulns[:max_vulns]
            add_log(f"📊 [{filename}] Limited to top {max_vulns}/{original_count} findings (mode: {self.scan_mode['label']})", "info")
        
        return vulns

# ==========================================
# 🚀 ORCHESTRATION PARALLÈLE INTELLIGENTE
# ==========================================

def run_enterprise_scan_parallel(target: str, profile_key: str, mode: str):
    """🔥 Version avec Semaphore GPU + garde-fous VRAM"""
    global gpu_semaphore
    
    scan_id = str(uuid.uuid4())[:8]
    scan_state.update({
        "id": scan_id,
        "is_scanning": True,
        "start_time": time.time(),
        "progress": 0,
        "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0},
        "logs": [],
        "vulnerabilities": [],
        "should_stop": False,
        "estimated_time": "Calcul...",
        "confidence_score": 0.0,
        "failed_analyses": 0,
        "successful_analyses": 0,
        "target_dir": None,
        "parallel_active": 0,
        "gpu_queue": 0
    })
    
    add_log(f"🛡️ Démarrage Session V2.4 GPU-Intelligent #{scan_id}")
    add_log(f"🚀 Mode: {mode.upper()} | Profil: {profile_key.upper()}")

    profile = PROFILES.get(profile_key, PROFILES["balanced"])
    
    # 🧠 Récupération des paramètres d'exécution depuis MODEL_PROFILES
    model = profile["model"]
    model_profile = MODEL_PROFILES.get(model, MODEL_PROFILES["_default"])
    
    max_parallel = model_profile["max_parallel"]
    base_timeout = model_profile["timeout_per_file"]
    is_eco = model_profile.get("eco_mode", False)
    
    # Mise à jour scan_state avec info d'exécution
    scan_state["execution_strategy"] = "sequential" if max_parallel == 1 else "parallel"
    scan_state["model_latency"] = model_profile["latency"]
    
    # 🔥 NOUVEAU : Initialiser le semaphore GPU selon le profil
    gpu_limit = GPU_LIMITS.get(profile_key, 2)
    gpu_semaphore = Semaphore(gpu_limit)
    add_log(f"🎯 Limite GPU: {gpu_limit} appels IA simultanés max", "info")
    
    add_log(f"🤖 Modèle : {profile['model']}", "info")
    add_log(f"📊 Contexte : {profile['ctx']} tokens", "info")
    
    # 🎨 Messages UX professionnels selon stratégie
    if is_eco:
        add_log("🟢 Mode Éco activé", "success")
        add_log("   ↳ Analyse séquentielle optimisée", "info")
        add_log("   ↳ Stabilité maximale - vitesse réduite", "info")
    else:
        add_log(f"⚡ Parallélisation: {max_parallel} fichiers simultanés", "info")

    tmp_dir = None
    target_dir = target
    
    try:
        if target.startswith(("http", "git@")):
            tmp_dir = tempfile.mkdtemp()
            add_log(f"📥 Clonage du dépôt...", "info")
            Repo.clone_from(target, tmp_dir)
            target_dir = tmp_dir
        
        scan_state["target_dir"] = target_dir
        
        files = []
        extensions = []
        
        # 🎯 Récupération de la configuration du mode de scan (sémantique)
        scan_mode_config = SCAN_MODES.get(mode, SCAN_MODES["deep"])
        extensions = scan_mode_config["file_extensions"]
        add_log(f"🎯 Mode: {scan_mode_config['label']} - {scan_mode_config['description']}", "info")
        add_log(f"📁 Extensions: {len(extensions)} types de fichiers", "info")

        exclude = {'node_modules', '.git', 'venv', 'dist', 'build', '__pycache__', '.venv'}
        
        for root, dirs, filenames in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for f in filenames:
                if f.endswith(extensions) or (mode == "devsecops" and f in ['Dockerfile', 'docker-compose.yml']):
                    files.append(os.path.join(root, f))
        
        total_files = len(files)
        scan_state["stats"]["files"] = total_files
        
        if total_files == 0:
            add_log("⚠️ Aucun fichier correspondant.", "warning")
            return

        # 🔥 NOUVEAUTÉ : Garde-fou VRAM pour profil TITAN sur gros projets
        if profile_key == "titan" and total_files > 30:
            add_log("⚠️ Gros projet détecté, réduction parallèle TITAN", "warning")
            max_parallel = 5
            add_log(f"🎯 Nouveau parallélisme: {max_parallel} fichiers", "info")

        engine = IntelligentGPUEngine(profile, scan_mode=mode)
        start_ts = time.time()
        
        add_log(f"🔥 Lancement analyse parallèle de {total_files} fichiers...", "info")
        
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            future_to_file = {}
            processed = 0
            
            for filepath in files:
                if scan_state["should_stop"]:
                    break
                future = executor.submit(engine.scan_file, filepath, os.path.basename(filepath))
                future_to_file[future] = filepath
            
            for future in as_completed(future_to_file):
                if scan_state["should_stop"]:
                    break
                
                filepath = future_to_file[future]
                filename = os.path.basename(filepath)
                processed += 1
                
                try:
                    vulns = future.result()
                    
                    if vulns:
                        for v in vulns:
                            v["id"] = len(scan_state["vulnerabilities"]) + 1
                            scan_state["vulnerabilities"].append(v)
                            
                            sev = v["severity"].lower()
                            if sev in scan_state["stats"]: 
                                scan_state["stats"][sev] += 1
                            
                            if v["severity"] in ["Critical", "High"]:
                                add_log(f"🚨 {v['severity']} : {v['title']}", "error")
                
                except Exception as e:
                    add_log(f"❌ Erreur traitement {filename}: {e}", "error")
                
                scan_state["progress"] = int((processed / total_files) * 100)
                elapsed = time.time() - start_ts
                avg_time = elapsed / processed
                remain = avg_time * (total_files - processed)
                scan_state["estimated_time"] = f"{int(remain)} sec"

        if scan_state["vulnerabilities"]:
            avg_confidence = sum(v["confidence"] for v in scan_state["vulnerabilities"]) / len(scan_state["vulnerabilities"])
            scan_state["confidence_score"] = round(avg_confidence, 2)
        
        if not scan_state["should_stop"]:
            add_log("✅ Audit terminé.", "success")
            add_log(f"📊 Confiance : {scan_state['confidence_score']}%", "info")
            add_log(f"✅ Succès : {scan_state['successful_analyses']}", "success")
            add_log(f"❌ Échecs : {scan_state['failed_analyses']}", "warning")
            
            scan_state["progress"] = 100
            scan_state["estimated_time"] = "Terminé"
            
            summary = {
                "id": scan_id,
                "date": datetime.now().isoformat(),
                "target": target,
                "profile": profile_key,
                "mode": mode,
                "stats": scan_state["stats"],
                "confidence_score": scan_state["confidence_score"],
                "score": 100 - (scan_state["stats"]["critical"]*20) - (scan_state["stats"]["high"]*10),
                "successful_analyses": scan_state["successful_analyses"],
                "failed_analyses": scan_state["failed_analyses"]
            }
            save_to_history(summary)

    except Exception as e:
        add_log(f"🔥 Erreur Critique : {str(e)}", "critical")
    finally:
        scan_state["is_scanning"] = False
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

# ==========================================
# 📡 ENDPOINTS API
# ==========================================

@app.post("/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if scan_state["is_scanning"]: 
        return {"success": False, "msg": "Occupé"}
    background_tasks.add_task(run_enterprise_scan_parallel, request.target, request.profile, request.mode)
    return {"success": True}

@app.post("/scan/stop")
async def stop_scan():
    scan_state["should_stop"] = True
    return {"success": True}

@app.get("/scan/status")
async def get_status():
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
    vuln_id = request.vuln_id
    vuln = next((v for v in scan_state["vulnerabilities"] if v["id"] == vuln_id), None)
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnérabilité non trouvée")
    
    filename = vuln.get("file", "unknown")
    add_log(f"🔧 Génération patch #{vuln_id} pour {filename}...", "info")
    
    result = generate_fix_patch(vuln)
    
    if result["success"]:
        add_log(f"✅ Patch généré avec succès : {result['patch_file']}", "success")
    else:
        error_msg = result.get("error", "Erreur inconnue")
        add_log(f"❌ Échec patch #{vuln_id} : {error_msg}", "error")
    
    return result

@app.get("/fix/download/{patch_file}")
async def download_patch(patch_file: str):
    patch_path = os.path.join(PATCHES_DIR, patch_file)
    
    if not os.path.exists(patch_path):
        raise HTTPException(status_code=404, detail="Patch non trouvé")
    
    return FileResponse(patch_path, media_type='text/plain', filename=patch_file)

@app.get("/export/report")
async def export_report_html():
    vulns_html = ""
    for v in scan_state["vulnerabilities"]:
        color = "red" if v['severity'] == 'Critical' else "orange" if v['severity'] == 'High' else "blue"
        confidence_color = "green" if v['confidence'] >= 70 else "orange" if v['confidence'] >= 40 else "red"
        
        reasoning = v.get("reasoning", {})
        reasoning_html = f"""
        <div class="reasoning">
            <h4>🧠 Profilage IA</h4>
            <p><strong>Pattern:</strong> {reasoning.get('pattern', 'N/A')}</p>
            {f"<p><strong>CVE:</strong> {', '.join(reasoning.get('cve_refs', []))}</p>" if reasoning.get('cve_refs') else ''}
            {f"<p><strong>CWE:</strong> {', '.join(reasoning.get('cwe_refs', []))}</p>" if reasoning.get('cwe_refs') else ''}
            {f"<p><strong>Impact Business:</strong> {reasoning.get('business_impact', 'N/A')}</p>" if reasoning.get('business_impact') != 'Non évalué' else ''}
            {f"<p><strong>Exploit:</strong> {reasoning.get('exploit_example', 'N/A')}</p>" if reasoning.get('exploit_example') != 'Non fourni' else ''}
        </div>
        """
        
        vulns_html += f"""
        <div class="vuln-card {v['severity']}">
            <h3>
                <span class="badge {color}">{v['severity']}</span> 
                {v['title']}
                <span class="confidence {confidence_color}">Confiance: {v['confidence']}%</span>
            </h3>
            <div class="meta">Fichier: <strong>{v['file']}</strong> | Ligne: {v['line'] or 'N/A'}</div>
            <p>{v['description']}</p>
            {reasoning_html}
            <div class="code-block"><pre>{v['snippet']}</pre></div>
            <div class="fix-block"><strong>Correction:</strong><pre>{v['fix']}</pre></div>
            {f'<div class="cve">🔗 CVE: {v["cve_reference"]}</div>' if v.get('cve_reference') else ''}
            {f'<div class="cwe">📋 CWE: {v["cwe_id"]}</div>' if v.get('cwe_id') else ''}
        </div>
        """
        
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Rapport Audit Nexus V2.4 GPU - {datetime.now().strftime('%Y-%m-%d')}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px; color: #333; }}
            h1 {{ border-bottom: 2px solid #6366f1; padding-bottom: 10px; }}
            .vuln-card {{ border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; page-break-inside: avoid; }}
            .vuln-card.Critical {{ border-left: 5px solid #ef4444; }}
            .vuln-card.High {{ border-left: 5px solid #f97316; }}
            .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; background-color: #ef4444; }}
            .confidence {{ float: right; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
            .confidence.green {{ background-color: #10b981; color: white; }}
            .reasoning {{ background: #eff6ff; border-left: 3px solid #3b82f6; padding: 10px; margin: 15px 0; border-radius: 4px; }}
            .code-block {{ background: #f1f5f9; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; margin: 10px 0; }}
            .fix-block {{ background: #ecfdf5; padding: 10px; border-radius: 4px; font-family: monospace; color: #065f46; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Nexus Auditor V2.4 GPU Intelligent Report</h1>
        <p>Date: {datetime.now().strftime('%d/%m/%Y %H:%M')} | Scan ID: {scan_state.get('id', 'N/A')}</p>
        <h2>Vulnérabilités ({len(scan_state["vulnerabilities"])})</h2>
        {vulns_html if vulns_html else "<p>Aucune vulnérabilité.</p>"}
    </body>
    </html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    print("🚀 Nexus Enterprise Backend V2.4 - GPU Intelligent Orchestration")
    print("✨ Fonctionnalités:")
    print("   - 🎯 Semaphore GPU (contrôle charge réelle)")
    print("   - ⏱️ Timeout intelligent (proportionnel)")
    print("   - 🛡️ Garde-fou VRAM (profil Titan)")
    print("   - 🔥 Profil TITAN (128k context, fichiers entiers)")
    print("   - ⚡ Analyse parallèle (8 fichiers simultanés max)")
    print("   - 🧠 Profilage IA avancé (CVE + CWE + Business Impact)")
    print("   - 🔧 Auto-Fix avec patches Git")
    print("   - 🎯 Optimisé pour RTX 5090, compatible M1 Mac")
    uvicorn.run(app, host="0.0.0.0", port=8000)