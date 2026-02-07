import os
import re
from typing import Dict, List, Optional


class ScanModeController:
    """Contrôleur de mode de scan + templates de prompts réutilisables."""

    HOTSPOT_KEYWORDS = (
        "auth", "login", "token", "password", "secret", "jwt", "oauth",
        "admin", "session", "crypto", "encrypt", "decrypt", "payment",
        "checkout", "wallet", "sql", "query", "db", "database", "exec",
        "command", "shell", "upload", "deserialize", "eval",
    )

    DEVSECOPS_KEYWORDS = (
        ".env", "secret", "token", "key", "docker", "compose",
        "k8s", "kubernetes", "helm", "terraform", "iac", "ci", "cd",
        "workflow", "gitlab-ci", "jenkins", "pipeline", "requirements",
        "package.json", "package-lock", "go.mod", "cargo.toml", "pom.xml",
        "build.gradle", "npmrc", "yarn.lock",
    )

    SECURITY_EXTENSIONS = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".php", ".java",
        ".go", ".rs", ".rb", ".cs", ".c", ".cpp", ".sql",
    }

    DEVSECOPS_EXTENSIONS = {
        ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".conf", ".cfg",
    }

    PROMPT_TEMPLATES = {
        "rapid": """You are a senior application security reviewer.

Mode: RAPID (surface scan + hotspots).
Goal:
- Prioritize high-impact issues only.
- Focus on risky auth/input/execution flows and obvious exploit paths.
- Skip style and non-security comments.

Return ONLY valid JSON array with this schema:
[
  {{
    "title": "string",
    "type": "string",
    "severity": "Critical|High|Medium|Low",
    "confidence": 0-100,
    "file": "string",
    "line": 0,
    "lines": "start-end",
    "evidence": "exact code",
    "description": "why vulnerable",
    "impact": "realistic impact",
    "recommendation": "specific mitigation",
    "fix": "optional patch guidance"
  }}
]

Rules:
- No speculation.
- If evidence is weak, return [].
- Prefer fewer findings with strong proof.

FILE: {filename}
LANGUAGE: {language}
CHUNK: {chunk_index}/{chunk_total}
HOTSPOT FOCUS: {hotspot_focus}

CODE:
```
{content}
```
""",
        "deep": """You are a senior application security reviewer.

Mode: DEEP (exhaustive + cross-file reasoning hints).
Goal:
- Analyze broad classes: injection, auth/session, crypto misuse, access control,
  insecure deserialization, SSRF/path traversal, secrets exposure.
- Use cross-file hints when relevant, but never fabricate proof.

Return ONLY valid JSON array with this schema:
[
  {{
    "title": "string",
    "type": "string",
    "severity": "Critical|High|Medium|Low",
    "confidence": 0-100,
    "file": "string",
    "line": 0,
    "lines": "start-end",
    "evidence": "exact code",
    "description": "why vulnerable",
    "impact": "realistic impact",
    "recommendation": "specific mitigation",
    "fix": "optional patch guidance"
  }}
]

Rules:
- Ground every claim in the provided code.
- If uncertain, lower confidence.
- Return [] when no confirmed issue exists.

FILE: {filename}
LANGUAGE: {language}
CHUNK: {chunk_index}/{chunk_total}
CROSS-FILE HINTS:
{cross_file_hints}

CODE:
```
{content}
```
""",
        "devsecops": """You are a senior DevSecOps security reviewer.

Mode: DEVSECOPS (secrets/config/IaC/CI-CD/dependencies + app code).
Goal:
- Detect exposed secrets, insecure CI/CD configs, weak container hardening,
  unsafe IaC defaults, dependency security anti-patterns, and app vulns.
- Include misconfigurations with concrete evidence.

Return ONLY valid JSON array with this schema:
[
  {{
    "title": "string",
    "type": "string",
    "severity": "Critical|High|Medium|Low",
    "confidence": 0-100,
    "file": "string",
    "line": 0,
    "lines": "start-end",
    "evidence": "exact config/code",
    "description": "why vulnerable",
    "impact": "realistic impact",
    "recommendation": "specific mitigation",
    "fix": "optional patch guidance"
  }}
]

Rules:
- No invented context.
- Prioritize actionable findings with remediation.
- Return [] if no confirmed issue.

FILE: {filename}
LANGUAGE: {language}
CHUNK: {chunk_index}/{chunk_total}
DEVSECOPS FOCUS: secrets, CI/CD, IaC, containers, dependencies

CODE:
```
{content}
```
""",
    }

    def resolve_mode_key(self, mode_key: Optional[str] = None, mode_config: Optional[Dict] = None) -> str:
        if isinstance(mode_key, str) and mode_key in {"rapid", "deep", "devsecops"}:
            return mode_key

        label = str((mode_config or {}).get("label", "")).lower()
        if "rapid" in label or "rapide" in label:
            return "rapid"
        if "devsecops" in label:
            return "devsecops"
        return "deep"

    def score_file(self, filepath: str, mode_key: str) -> Dict:
        path = filepath.replace("\\", "/")
        lowered = path.lower()
        base = os.path.basename(lowered)
        ext = os.path.splitext(base)[1]

        score = 0
        reasons: List[str] = []

        if ext in self.SECURITY_EXTENSIONS:
            score += 20
            reasons.append("app-code")

        if any(keyword in lowered for keyword in self.HOTSPOT_KEYWORDS):
            score += 35
            reasons.append("hotspot-keyword")

        if mode_key == "rapid":
            if "/test" in lowered or "/spec" in lowered:
                score -= 15
                reasons.append("test-file")
            if lowered.endswith((".md", ".txt", ".svg")):
                score -= 20
                reasons.append("low-signal")

        if mode_key == "devsecops":
            if ext in self.DEVSECOPS_EXTENSIONS:
                score += 25
                reasons.append("config-ext")
            if base in {
                "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                ".gitlab-ci.yml", "requirements.txt", "package.json",
                "package-lock.json", "go.mod", "cargo.toml",
            }:
                score += 40
                reasons.append("devsecops-critical-file")
            if any(keyword in lowered for keyword in self.DEVSECOPS_KEYWORDS):
                score += 30
                reasons.append("devsecops-keyword")

        if mode_key == "deep":
            # Deep mode privilégie l'exhaustif; scoring juste pour un ordre stable.
            if ext in self.SECURITY_EXTENSIONS:
                score += 10

        return {"path": filepath, "score": score, "reasons": reasons}

    def prioritize_files(self, files: List[str], mode_key: str) -> List[Dict]:
        mode = self.resolve_mode_key(mode_key=mode_key)
        scored = [self.score_file(path, mode) for path in files]

        if mode == "deep":
            return sorted(scored, key=lambda x: x["path"])

        return sorted(scored, key=lambda x: (-x["score"], x["path"]))

    def build_analysis_prompt(
        self,
        mode_key: str,
        filename: str,
        content: str,
        language: str = "unknown",
        chunk_index: int = 1,
        chunk_total: int = 1,
        hotspot_reasons: Optional[List[str]] = None,
        cross_file_hints: Optional[List[str]] = None,
    ) -> str:
        mode = self.resolve_mode_key(mode_key=mode_key)
        template = self.PROMPT_TEMPLATES[mode]

        hotspot_focus = ", ".join(sorted(set(hotspot_reasons or []))) if hotspot_reasons else "none"
        hints = cross_file_hints or []
        hints_text = "\n".join(f"- {h}" for h in hints[:8]) if hints else "- none"

        return template.format(
            filename=filename,
            content=content,
            language=language,
            chunk_index=chunk_index,
            chunk_total=chunk_total,
            hotspot_focus=hotspot_focus,
            cross_file_hints=hints_text,
        )

    def update_cross_file_hints(self, existing_hints: List[str], filename: str, findings: List[Dict], max_hints: int = 12) -> List[str]:
        hints = list(existing_hints or [])
        seen = set(hints)

        for finding in findings:
            f_type = str(finding.get("type", "UNKNOWN")).upper()[:48]
            line = finding.get("line")
            line_part = f":{line}" if isinstance(line, int) and line > 0 else ""
            hint = f"{f_type}@{filename}{line_part}"
            if hint not in seen:
                hints.append(hint)
                seen.add(hint)
            if len(hints) >= max_hints:
                break

        return hints[-max_hints:]

