# Backend Dockerfile - Nexus AI Auditor
# Base image Python légère
FROM python:3.11-slim

# Définir le répertoire de travail
WORKDIR /app

# Installer git (requis pour GitPython)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Copier requirements et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code backend
COPY backend.py .

# Créer les répertoires nécessaires
RUN mkdir -p audit_logs/raw_responses audit_logs/patches

# Exposer le port de l'API
EXPOSE 8000

# Variables d'environnement par défaut
ENV OLLAMA_URL="http://host.docker.internal:11434/api/generate"
ENV TITAN_MODEL="qwen2.5-coder:32b"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)"

# Lancer l'application
CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
