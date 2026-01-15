#!/bin/bash
echo "🧹 Cleaning up Docker containers..."
docker-compose down

echo "🧹 Cleaning pycache..."
rm -rf backend/__pycache__

echo "🏗️ Rebuilding Backend (No Cache)..."
docker-compose build --no-cache nexus-backend

echo "🚀 Starting Backend..."
docker-compose up -d nexus-backend

echo "📜 Tailing Logs (Ctrl+C to stop)..."
docker-compose logs -f nexus-backend
