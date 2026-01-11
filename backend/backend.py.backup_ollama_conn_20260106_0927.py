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
import signal
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from git import Repo

# ==========================================
# ⚙️ NEXUS AUDITOR V2.5 STABLE
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

# ==========================================
# 🤖 GESTION AUTOMATIQUE DES MODÈLES
# ==========================================

def get_installed_models() -> set:
    """Récupère la liste des modèles installés dans Ollama"""
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            models = {m.get("name", "") for m in data.get("models", [])}
            return models
    except Exception as e:
        print(f"[Ollama] ⚠️ Impossible de lister les modèles: {e}")
    return set()

def is_model_installed(model_name: str) -> bool:
    """Vérifie si un modèle spécifique est installé"""
    installed = get_installed_models()
    # Vérifier nom exact ou sans tag
    return model_name in installed or model_name.split(":")[0] in {m.split(":")[0] for m in installed}

def pull_model(model_name: str) -> bool:
    """Télécharge un modèle Ollama (peut prendre du temps)"""
    print(f"[Ollama] 📥 Téléchargement du modèle {model_name}...")
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=3600  # 1 heure max pour les gros modèles
        )
        if response.status_code == 200:
            print(f"[Ollama] ✅ Modèle {model_name} installé avec succès")
            return True
        else:
            print(f"[Ollama] ❌ Erreur téléchargement: {response.status_code}")
            return False
    except Exception as e:
        print(f"[Ollama] ❌ Erreur: {e}")
        return False

def ensure_model_available(model_name: str) -> bool:
    """Vérifie et installe le modèle si nécessaire. Retourne True si disponible."""
    if is_model_installed(model_name):
        print(f"[Ollama] ✅ Modèle {model_name} déjà installé")
        return True
    
    print(f"[Ollama] ⚠️ Modèle {model_name} non trouvé, installation en cours...")
    return pull_model(model_name)



# ==========================================
# 🧠 PROMPT IA STRICT (ANTI-HALLUCINATION)
# ==========================================
# Ce prompt est COURT et STRICT - NE PAS ALOURDIR
# NOTE: Les accolades JSON sont doublées {{}} pour éviter les conflits avec .format()

CORE_PROMPT = """You are a security code auditor.

Your task is to identify REAL and CONFIRMED security vulnerabilities
based solely on the provided code.

Rules:
- Do not invent vulnerabilities.
- Do not speculate.
- Do not assume external context.
- If unsure, return no finding.

For each vulnerability:
- Provide the exact code snippet as evidence.
- Explain why it is vulnerable.
- Describe a realistic exploitation scenario.

Return ONLY a JSON array with this schema:
[{{
  "type": "string",
  "severity": "Critical|High|Medium|Low",
  "confidence": 0-100,
  "line": <line_number>,
  "title": "short title",
  "description": "short factual description",
  "evidence": "exact code snippet",
  "impact": "realistic impact",
  "fix": "specific mitigation code"
}}]

If no confirmed vulnerability exists, return: []

CODE FILE ({filename}):
```
{content}
```
"""

# ==========================================
# ⚡ PROFILS DE PUISSANCE (INFRASTRUCTURE)
# ==========================================
# Les profils contrôlent CE QUE LA MACHINE PEUT ENCAISSER
# V2.5: Qwen2.5-Coder 7B en eco (moins d'hallucinations)

POWER_PROFILES = {
    "eco": {
        "label": "🍃 Eco (Mac M1 / CPU)",
        "description": "Stabilité maximale, séquentiel",
        "model": "qwen2.5-coder:7b",  # V2.5: Changé de deepseek
        "num_ctx": 8192,
        "num_predict": 1024,  # V2.5: Réduit pour réponses concises
        "chunk_size": 6000,
        "timeout": 90,  # V2.5: Réduit
        "parallel_files": 1,
    },
    "balanced": {
        "label": "⚖️ Balanced (RTX 3060)",
        "description": "Précision stable, séquentiel",
        "model": "qwen2.5-coder:14b",
        "num_ctx": 16384,
        "num_predict": 2048,  # V2.5: Réduit
        "chunk_size": 10000,
        "timeout": 120,  # V2.5: Réduit
        "parallel_files": 1,
    },
    "elite": {
        "label": "🚀 Elite (RTX 3090/4090)",
        "description": "Analyse avancée, parallélisme modéré",
        "model": "qwen2.5-coder:32b",
        "num_ctx": 32768,
        "num_predict": 4096,
        "chunk_size": 15000,
        "timeout": 180,  # V2.5: Réduit
        "parallel_files": 2,
    },
    "titan": {
        "label": "🔥 Titan (RTX 5090 / Enterprise)",
        "description": "Audit exhaustif entreprise",
        "model": "qwen2.5-coder:32b",
        "num_ctx": 65536,
        "num_predict": 8192,
        "chunk_size": 25000,
        "timeout": 300,
        "parallel_files": 4,
    }
}

# ==========================================
# 🎯 MODES DE SCAN (BUDGET PRODUIT)
# ==========================================
# V2.5: Budgets stricts, seuils confiance ajustés

SCAN_MODES = {
    "rapid": {
        "label": "⚡ Rapide",
        "description": "Rapide, ciblé, peu de résultats",
        "max_files": 30,  # V2.5: Réduit de 50 à 30
        "max_time_per_file": 20,  # V2.5: Réduit
        "max_vulns_per_file": 3,
        "min_severity": "High",
        "min_confidence": 85,  # V2.5: Augmenté de 70 à 85
        "num_predict_override": 256,  # V2.5: Réponses ultra-courtes
        "file_extensions": ('.py', '.js', '.ts', '.php', '.java', '.go'),
    },
    "deep": {
        "label": "🧠 Profond",
        "description": "Équilibré, précis",
        "max_files": 100,  # V2.5: Réduit de 200 à 100
        "max_time_per_file": 60,  # V2.5: Réduit
        "max_vulns_per_file": 10,
        "min_severity": "Medium",
        "min_confidence": 50,
        "num_predict_override": None,  # Utilise le profil
        "file_extensions": ('.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', 
                           '.c', '.cpp', '.rs', '.go', '.sql'),
    },
    "devsecops": {
        "label": "🔐 DevSecOps",
        "description": "Exhaustif, long assumé",
        "max_files": None,
        "max_time_per_file": 180,
        "max_vulns_per_file": None,
        "min_severity": "Low",
        "min_confidence": 30,
        "num_predict_override": None,
        "file_extensions": ('.yaml', '.yml', '.json', '.env', '.toml',
                           '.py', '.js', '.ts', '.go', '.java', '.php',
                           'Dockerfile', 'docker-compose.yml'),
    }
}

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

app = FastAPI(title="Nexus Auditor Enterprise API V2.5 Stable")

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
    "budget_info": {}
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
    Retourne (line_start, line_end) ou (None, None) si non trouvé.
    """
    if not evidence or not file_content:
        return (None, None)
    
    evidence_clean = evidence.strip()
    if not evidence_clean:
        return (None, None)
    
    lines = file_content.split('\n')
    
    # Chercher la preuve dans le fichier
    for i, line in enumerate(lines, start=1):
        if evidence_clean in line:
            return (i, i)  # Ligne unique pour l'instant
        
    # Si preuve multi-lignes, chercher le début
    evidence_lines = evidence_clean.split('\n')
    if len(evidence_lines) > 1:
        for i in range(len(lines) - len(evidence_lines) + 1):
            match = True
            for j, ev_line in enumerate(evidence_lines):
                if ev_line.strip() not in lines[i + j]:
                    match = False
                    break
            if match:
                return (i + 1, i + len(evidence_lines))
    
    return (None, None)

# ==========================================
# 🚨 ECO RULE #5: POLITIQUE DE SÉVÉRITÉ
# ==========================================

def apply_eco_severity_policy(vuln: dict, evidence: str, file_content: str) -> str:
    """
    ECO: Critical est RARE. Downgrade si preuve faible.
    Conditions pour Critical:
    - Preuve claire ET
    - Impact direct ET
    - Exploit réaliste
    """
    severity = vuln.get("severity", "Low")
    
    if severity != "Critical":
        return severity  # Pas de downgrade nécessaire
    
    # Vérifier la force de la preuve
    has_strong_evidence = False
    
    # Check 1: Evidence textuelle présente
    if evidence and file_content and evidence.strip() in file_content:
        has_strong_evidence = True
    
    # Check 2: Confidence très haute (≥ 90)
    if vuln.get("confidence", 0) >= 90:
        has_strong_evidence = True
    
    # Check 3: Impact et exploit bien documentés
    impact = vuln.get("impact", "")
    description = vuln.get("description", "")
    if len(impact) > 50 and len(description) > 100:
        # Impact et description détaillés = sérieux
        has_strong_evidence = True
    
    # ECO: Si preuve faible, downgrade Critical → High
    if not has_strong_evidence:
        add_log(f"⬇️ ECO Downgrade: Critical → High (preuve faible)", "info")
        return "High"
    
    return "Critical"


# ==========================================
# 🎯 FILTRAGE POST-IA (LOGIQUE AUTOUR DU MOTEUR)
# ==========================================

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
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
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
    
    filtered = []
    for v in vulns:
        title = v.get('title', 'N/A')
        vuln_type = v.get('type', '').upper()
        vuln_sev = severity_order.get(v.get("severity", "Low"), 0)
        vuln_conf = v.get("confidence", 0)
        
        # ==========================================
        # FILTRE 1: Sévérité minimum
        # ==========================================
        if vuln_sev < min_sev:
            add_log(f"🗑️ Filtré (sévérité): {title} ({v.get('severity')})", "info")
            continue
        
        # ==========================================
        # FILTRE 2: Confiance minimum (V2.5: seuils stricts)
        # ==========================================
        if vuln_conf < min_conf:
            add_log(f"🗑️ Filtré (confiance): {title} ({vuln_conf}%)", "info")
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
                evidence_clean = evidence.strip()
                if len(evidence_clean) > 10 and evidence_clean not in file_content:
                    evidence_normalized = ' '.join(evidence_clean.split())
                    file_normalized = ' '.join(file_content.split())
                    if evidence_normalized not in file_normalized:
                        add_log(f"🔍 Filtré (preuve textuelle absente): {title}", "warning")
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
                    # Au moins 2 identifiants doivent exister dans le fichier
                    matches = sum(1 for ident in identifiers if ident in file_content)
                    if matches >= 2 or (len(identifiers) == 1 and matches == 1):
                        has_valid_proof = True
            
            # Check 3: Preuve textuelle exacte (bonus)
            if not has_valid_proof and evidence and file_content:
                evidence_clean = evidence.strip()
                if len(evidence_clean) > 5 and evidence_clean in file_content:
                    has_valid_proof = True
            
            # Si aucune preuve valide en Deep, on filtre (mais moins strict qu'en Rapid)
            if not has_valid_proof and evidence:
                add_log(f"🔍 Filtré (preuve structurelle insuffisante): {title}", "info")
                continue
        
        # ==========================================
        # FILTRE 4: V2.5 - Vulnérabilités impossibles par langage
        # ==========================================
        if file_ext in LANGUAGE_FORBIDDEN:
            forbidden_types = LANGUAGE_FORBIDDEN[file_ext]
            is_forbidden = False
            for forbidden in forbidden_types:
                if forbidden.upper() in vuln_type or forbidden.upper() in title.upper():
                    add_log(f"🚫 Filtré (impossible en {file_ext}): {title} ({forbidden})", "warning")
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
    
    # ECO RULE #6: Calculer les lignes à partir de l'evidence, pas de l'IA
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
    
    # ECO RULE #5: Appliquer politique de sévérité
    sev_raw = str(vuln.get("severity", "Low")).capitalize()
    if "crit" in sev_raw.lower():
        sev = "Critical"
    elif "high" in sev_raw.lower():
        sev = "High"
    elif "med" in sev_raw.lower():
        sev = "Medium"
    else:
        sev = "Low"
    
    # ECO: Downgrade Critical si preuve faible
    sev = apply_eco_severity_policy(vuln, evidence, file_content)
    
    confidence = calculate_confidence(vuln, raw_response, filepath)
    
    return {
        "file": filename,
        "filepath": filepath,
        "title": vuln.get("title", vuln.get("type", "Vulnérabilité Inconnue")),
        "severity": sev,
        "line": line_start,  # ECO: Calculé par le moteur
        "line_end": line_end,  # ECO: Range si multi-ligne
        "description": vuln.get("description", "Pas de description fournie."),
        "fix": vuln.get("fix", vuln.get("recommendation", "Pas de correctif proposé.")),
        "confidence": round(confidence, 2),
        "snippet": snippet,
        "type": vuln.get("type", "Unknown"),
        "impact": vuln.get("impact", "Non évalué"),
        "timestamp": datetime.now().isoformat()
    }


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
    
    def __init__(self, profile_config: dict, mode_config: dict):
        self.profile = profile_config
        self.mode = mode_config
        self.fallback_model = "qwen2.5-coder:7b"  # V2.5: Fallback cohérent

    def call_ollama(self, prompt: str, filename: str, max_retries=2) -> Optional[dict]:
        """Appel IA simple avec retry et fallback"""
        timeout = self.profile.get("timeout", 180)
        model = self.profile["model"]
        
        # V2.5: Utiliser num_predict du mode si override défini (Rapid = très court)
        num_predict = self.mode.get("num_predict_override") or self.profile["num_predict"]
        
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    add_log(f"🔄 Retry {attempt+1}/{max_retries} pour {filename}", "warning")
                    time.sleep(2 ** attempt)
                
                add_log(f"🤖 Analyse: {filename} (modèle: {model})", "info")
                
                response = requests.post(
                    OLLAMA_URL,
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": {
                            "temperature": 0.1,
                            "num_ctx": self.profile["num_ctx"],
                            "num_predict": num_predict  # V2.5: Peut être overridé par mode
                        }
                    },
                    timeout=timeout
                )
                
                if response.status_code == 200:
                    raw_text = response.json().get('response', '{}')
                    save_raw_response(filename, raw_text)
                    
                    parsed = extract_json_from_text(raw_text)
                    
                    if parsed is not None:
                        add_log(f"✅ Réponse valide pour {filename}", "success")
                        return {"data": parsed, "raw": raw_text}
                    else:
                        add_log(f"⚠️ JSON invalide pour {filename}", "warning")
                        continue
                else:
                    add_log(f"❌ HTTP {response.status_code} pour {filename}", "error")
                    
            except requests.exceptions.Timeout:
                add_log(f"⏱️ Timeout ({timeout}s) pour {filename}", "warning")
            except Exception as e:
                add_log(f"❌ Erreur: {str(e)[:100]}", "error")
        
        # ECO RULE #1: Pas de fallback retry - 1 fichier = 1 appel
        return None


    def scan_file(self, filepath: str, filename: str) -> list:
        """
        ECO RULE: 1 fichier = 1 appel IA
        Pas de chunking, pas de retry, pas de multi-pass.
        """
        if scan_state["should_stop"]:
            return []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return []
            
            # ECO: Si fichier trop gros, on tronque (pas de chunking)
            chunk_size = self.profile["chunk_size"]
            if len(content) > chunk_size:
                add_log(f"⚠️ {filename}: fichier tronqué ({len(content)} → {chunk_size} chars)", "warning")
                content = content[:chunk_size]
            
            scan_state["current_file"] = filename
            
            # ECO: 1 SEUL appel IA par fichier
            prompt = CORE_PROMPT.format(filename=filename, content=content)
            
            # ECO: Timer pour dégradation de confiance si budget dépassé
            file_start = time.time()
            result = self.call_ollama(prompt, filename, max_retries=1)  # ECO: 1 retry max
            file_duration = time.time() - file_start
            
            all_vulns = []
            
            if result:
                data = result["data"]
                raw_response = result["raw"]
                
                if isinstance(data, dict):
                    data = [data]
                
                if isinstance(data, list):
                    for v in data:
                        if not isinstance(v, dict):
                            add_log(f"⚠️ Élément ignoré (pas un dict): {type(v).__name__}", "warning")
                            continue
                        
                        # ECO: Passer le contenu pour calcul de lignes et politique sévérité
                        normalized = normalize_vulnerability(v, filepath, filename, raw_response, content)
                        
                        # ECO RULE 2: Budget = dégradation de confiance
                        budget = self.mode.get("max_time_per_file", 60)
                        if file_duration > budget:
                            normalized["confidence"] *= 0.85
                            add_log(f"⏱️ Budget dépassé ({file_duration:.0f}s > {budget}s), confiance dégradée", "info")
                        
                        all_vulns.append(normalized)
                    
                    scan_state["successful_analyses"] += 1
            else:
                scan_state["failed_analyses"] += 1
                # ECO: Pas de retry, on continue
            
            # Filtrage POST-IA selon le mode (avec contenu pour validation preuve)
            filtered_vulns = apply_mode_filters(all_vulns, self.mode, filepath, content)
            
            return filtered_vulns

        except Exception as e:
            add_log(f"❌ Erreur analyse {filename}: {e}", "error")
            scan_state["failed_analyses"] += 1
            return []


# ==========================================
# 🚀 ORCHESTRATION DU SCAN
# ==========================================

def run_scan(target: str, profile_key: str, mode_key: str):
    """Orchestration principale du scan"""
    scan_id = str(uuid.uuid4())[:8]
    
    profile = POWER_PROFILES.get(profile_key, POWER_PROFILES["balanced"])
    mode = SCAN_MODES.get(mode_key, SCAN_MODES["deep"])
    
    scan_state.update({
        "id": scan_id,
        "is_scanning": True,
        "start_time": time.time(),
        "progress": 0,
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
            "min_confidence": mode["min_confidence"]
        }
    })
    
    add_log(f"🛡️ Nexus V2.5 Stable - Session #{scan_id}")
    add_log(f"📊 Profil: {profile['label']} | Mode: {mode['label']}")
    add_log(f"🎯 Budget: max {mode['max_files'] or '∞'} fichiers, sévérité ≥ {mode['min_severity']}")

    # V2.5: Vérification et installation automatique du modèle
    model_name = profile["model"]
    add_log(f"🤖 Vérification du modèle {model_name}...", "info")
    if not ensure_model_available(model_name):
        add_log(f"❌ Impossible d'installer le modèle {model_name}. Scan annulé.", "critical")
        scan_state["is_scanning"] = False
        return

    tmp_dir = None
    target_dir = target
    
    try:
        # Clone si URL Git
        if target.startswith(("http", "git@")):
            tmp_dir = tempfile.mkdtemp()
            add_log(f"📥 Clonage du dépôt...", "info")
            Repo.clone_from(target, tmp_dir)
            target_dir = tmp_dir
        
        scan_state["target_dir"] = target_dir
        
        # Collecte des fichiers selon le mode
        files = []
        extensions = mode["file_extensions"]
        exclude = {'node_modules', '.git', 'venv', 'dist', 'build', '__pycache__', '.venv'}
        
        for root, dirs, filenames in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for f in filenames:
                # V2.5: Ignorer fichiers build-time en Rapid/Deep
                if mode_key in ("rapid", "deep") and f in BUILD_TIME_FILES:
                    continue
                if f.endswith(extensions) or (mode_key == "devsecops" and f in ['Dockerfile', 'docker-compose.yml']):
                    files.append(os.path.join(root, f))
        
        # Limiter selon le mode
        max_files = mode["max_files"]
        if max_files and len(files) > max_files:
            add_log(f"✂️ Limite mode {mode_key}: {len(files)} → {max_files} fichiers", "info")
            files = files[:max_files]
            scan_state["stats"]["skipped"] = len(files) - max_files
        
        total_files = len(files)
        scan_state["stats"]["files"] = total_files
        
        if total_files == 0:
            add_log("⚠️ Aucun fichier correspondant aux critères.", "warning")
            return

        add_log(f"📁 {total_files} fichiers à analyser", "info")

        engine = StableEngine(profile, mode)
        start_ts = time.time()
        
        for i, filepath in enumerate(files):
            if scan_state["should_stop"]:
                add_log("🛑 Scan interrompu par l'utilisateur", "warning")
                break
            
            # Estimation temps restant
            elapsed = time.time() - start_ts
            if i > 0:
                avg_time = elapsed / i
                remain = avg_time * (total_files - i)
                scan_state["estimated_time"] = f"{int(remain)} sec"
            
            filename = os.path.basename(filepath)
            
            # Timeout par fichier selon le mode
            file_start = time.time()
            vulns = engine.scan_file(filepath, filename)
            file_duration = time.time() - file_start
            
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
                "failed_analyses": scan_state["failed_analyses"]
            }
            save_to_history(summary)

    except Exception as e:
        add_log(f"🔥 Erreur Critique: {str(e)}", "critical")
    finally:
        scan_state["is_scanning"] = False

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
    background_tasks.add_task(run_scan, request.target, request.profile, request.mode)
    return {"success": True, "msg": f"Scan lancé (profil: {request.profile}, mode: {request.mode})"}

@app.post("/scan/stop")
async def stop_scan():
    """Arrête le scan en cours"""
    scan_state["should_stop"] = True
    scan_state["is_scanning"] = False
    add_log("🛑 Arrêt demandé par l'utilisateur", "warning")
    return {"success": True, "message": "Scan stopping..."}

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
        <title>Nexus Auditor V2.5 Report - {datetime.now().strftime('%Y-%m-%d')}</title>
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
                <h1>🛡️ Nexus Auditor V2.5 Stable Report</h1>
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
    print("🛡️ Nexus Auditor V2.5 Stable")
    print("=" * 60)
    print("✨ Basé sur V2.2 (moteur stable)")
    print("✨ Prompt IA strict anti-hallucination")
    print("✨ Profils de puissance: eco, balanced, elite, titan")
    print("✨ Modes de scan: rapid, deep, devsecops")
    print("✨ Filtrage POST-IA selon le mode")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
