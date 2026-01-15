#!/bin/bash
echo "🧹 Nettoyage complet Docker..."
docker-compose down -v

echo "🧹 Suppression du cache Python..."
rm -rf backend/__pycache__

echo "🏗️ Rebuild COMPLET (No Cache)..."
docker-compose build --no-cache nexus-backend

echo "🚀 Démarrage Backend..."
docker-compose up -d nexus-backend

echo "📜 Affichage des logs (Ctrl+C pour arrêter)..."
docker-compose logs -f nexus-backend
