#!/bin/bash
# Valkas Protection - VPS Security Dashboard
# Setup & Run Script

echo "╔══════════════════════════════════════════╗"
echo "║   VALKAS PROTECTION - Setup Script       ║"
echo "╚══════════════════════════════════════════╝"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 not found. Install it first."
    exit 1
fi

# Install dependencies
echo "[*] Installing dependencies..."
pip3 install -r requirements.txt

# Open firewall port 2026 (if ufw is available)
if command -v ufw &>/dev/null; then
    echo "[*] Opening port 2026 in UFW firewall..."
    ufw allow 2026/tcp
fi

echo ""
echo "[✓] Setup complete!"
echo ""
echo "┌──────────────────────────────────────────────┐"
echo "│  Valkas Protection - First Run               │"
echo "│                                              │"
echo "│  Open your browser and visit:               │"
echo "│  http://YOUR_VPS_IP:2026/install            │"
echo "│                                              │"
echo "│  The installation wizard will guide you to: │"
echo "│   1. Enter your license key                 │"
echo "│   2. Set your admin email & password        │"
echo "│   3. Set your advanced security password    │"
echo "└──────────────────────────────────────────────┘"
echo ""
echo "[*] Starting Valkas Protection on port 2026..."
echo "[*] Access: http://YOUR_VPS_IP:2026"
echo ""

python3 app.py
