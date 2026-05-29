#!/bin/bash
# ╔══════════════════════════════════════════════════╗
# ║        VALKAS PROTECTION - Installer             ║
# ║        github.com/valkasprotection/install       ║
# ╚══════════════════════════════════════════════════╝

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║        🛡️  VALKAS PROTECTION v2.0            ║"
echo "  ║        VPS Security Dashboard                ║"
echo "  ║        github.com/valkasprotection           ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
sleep 1

# ── Root check ──────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR]${NC} Please run as root: ${YELLOW}sudo bash install.sh${NC}"
  exit 1
fi

# ── Detect OS ───────────────────────────────────────
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS="unknown"
fi
echo -e "${CYAN}[*]${NC} Detected OS: ${BOLD}$OS${NC}"

# ── Dependencies ────────────────────────────────────
echo -e "${CYAN}[*]${NC} Updating package lists..."
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
  apt-get update -qq
  echo -e "${CYAN}[*]${NC} Installing Python3, pip, unzip..."
  apt-get install -y python3 python3-pip unzip curl ufw -qq
elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" ]]; then
  yum update -y -q
  echo -e "${CYAN}[*]${NC} Installing Python3, pip, unzip..."
  yum install -y python3 python3-pip unzip curl -q
elif [[ "$OS" == "arch" ]]; then
  pacman -Sy --noconfirm python python-pip unzip curl ufw -q
else
  echo -e "${YELLOW}[WARN]${NC} Unknown OS. Attempting generic install..."
fi

# ── Python packages ─────────────────────────────────
echo -e "${CYAN}[*]${NC} Installing Python packages..."
pip3 install flask psutil --quiet

# ── Download Valkas Protection ───────────────────────
INSTALL_DIR="/opt/valkas-protection"
echo -e "${CYAN}[*]${NC} Downloading Valkas Protection..."

if [ -d "$INSTALL_DIR" ]; then
  echo -e "${YELLOW}[!]${NC} Existing installation found at $INSTALL_DIR — backing up..."
  mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
fi

mkdir -p "$INSTALL_DIR"

# Download from GitHub releases
DOWNLOAD_URL="https://github.com/valkasprotection/install/releases/latest/download/valkas-protection.zip"
curl -L "$DOWNLOAD_URL" -o /tmp/valkas-protection.zip --silent --show-error

if [ $? -ne 0 ]; then
  echo -e "${RED}[ERROR]${NC} Download failed. Check your internet connection."
  exit 1
fi

unzip -q /tmp/valkas-protection.zip -d /tmp/valkas-unpack/
cp -r /tmp/valkas-unpack/valkas-protection/. "$INSTALL_DIR/"
rm -rf /tmp/valkas-protection.zip /tmp/valkas-unpack/
chmod +x "$INSTALL_DIR/start.sh"

echo -e "${GREEN}[✓]${NC} Files installed to $INSTALL_DIR"

# ── Firewall ─────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Opening port 2026 in firewall..."
if command -v ufw &>/dev/null; then
  ufw allow 2026/tcp > /dev/null 2>&1
  echo -e "${GREEN}[✓]${NC} UFW: port 2026 opened"
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-port=2026/tcp > /dev/null 2>&1
  firewall-cmd --reload > /dev/null 2>&1
  echo -e "${GREEN}[✓]${NC} firewalld: port 2026 opened"
else
  echo -e "${YELLOW}[!]${NC} No firewall manager found — open port 2026 manually if needed"
fi

# ── Systemd service ──────────────────────────────────
echo -e "${CYAN}[*]${NC} Creating systemd service..."
cat > /etc/systemd/system/valkas-protection.service << SERVICE
[Unit]
Description=Valkas Protection - VPS Security Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload > /dev/null 2>&1
systemctl enable valkas-protection > /dev/null 2>&1
systemctl start valkas-protection > /dev/null 2>&1

sleep 2

if systemctl is-active --quiet valkas-protection; then
  echo -e "${GREEN}[✓]${NC} Service started and enabled on boot"
else
  echo -e "${YELLOW}[!]${NC} Service may not have started — check: systemctl status valkas-protection"
fi

# ── Get server IP ────────────────────────────────────
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

# ── Done ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║       ✅  Installation Complete!             ║"
echo "  ╠══════════════════════════════════════════════╣"
echo -e "  ║  Panel URL:  ${CYAN}http://$SERVER_IP:2026${GREEN}         "
echo "  ║                                              ║"
echo "  ║  Open the URL in your browser.              ║"
echo "  ║  You will be asked to:                      ║"
echo "  ║    1. Enter your license key                ║"
echo "  ║    2. Set admin email & password            ║"
echo "  ║    3. Set advanced security password        ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║  Manage service:                            ║"
echo "  ║    systemctl status valkas-protection       ║"
echo "  ║    systemctl restart valkas-protection      ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
