#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  python3 -m venv venv
  venv/bin/pip install -r requirements.txt
fi

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

echo "Starting ShieldScan on http://127.0.0.1:8000"
exec venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
