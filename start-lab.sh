#!/usr/bin/env bash
# Start DVWA (+ optional ZAP and Juice Shop) for ShieldScan lab demos
set -e
cd "$(dirname "$0")"

DOCKER="docker"
COMPOSE="docker compose"

if ! docker info &>/dev/null; then
  if sudo -n docker info &>/dev/null 2>&1; then
    DOCKER="sudo docker"
    COMPOSE="sudo docker compose"
    echo "Using sudo for Docker (add yourself to the docker group to avoid this)"
  else
    echo "=============================================="
    echo "Docker permission denied."
    echo "Run ONCE in your terminal (enter your password):"
    echo ""
    echo "  sudo usermod -aG docker \$USER"
    echo "  newgrp docker"
    echo ""
    echo "Then run this script again:"
    echo "  ./start-lab.sh"
    echo "=============================================="
    echo ""
    echo "Or start DVWA immediately with sudo:"
    echo "  sudo docker compose up -d dvwa"
    exit 1
  fi
fi

MODE="${1:-dvwa}"
case "$MODE" in
  dvwa)
    echo "Starting DVWA only..."
    $COMPOSE up -d dvwa
    ;;
  full)
    echo "Starting DVWA + OWASP ZAP + Juice Shop..."
    $COMPOSE up -d
    ;;
  zap)
    echo "Starting OWASP ZAP..."
    $COMPOSE up -d zap
    ;;
  *)
    echo "Usage: $0 [dvwa|full|zap]"
    exit 1
    ;;
esac

echo ""
echo "Waiting for services..."
sleep 5

if $COMPOSE ps dvwa 2>/dev/null | grep -q "Up\|running"; then
  echo ""
  echo "DVWA is running:  http://127.0.0.1:4280"
  echo ""
  echo "First-time setup:"
  echo "  1. Open http://127.0.0.1:4280"
  echo "  2. Click 'Create / Reset Database'"
  echo "  3. Login: admin / password"
  echo "  4. Set Security Level to Low (DVWA Security menu)"
  echo "  5. Scan in ShieldScan: http://127.0.0.1:4280"
fi

if $COMPOSE ps zap 2>/dev/null | grep -q "Up\|running"; then
  echo "ZAP API:          http://127.0.0.1:8081"
  echo "Set SCANNER_MODE=zap in .env for full DAST scans"
fi

if $COMPOSE ps juiceshop 2>/dev/null | grep -q "Up\|running"; then
  echo "Juice Shop:       http://127.0.0.1:3000"
fi

echo ""
$COMPOSE ps
