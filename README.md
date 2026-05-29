# 🛡️ Valkas Protection — VPS Security Dashboard

A real-time VPS monitoring and DDoS protection dashboard built with Python + Flask.

---

## 🚀 Quick Start

```bash
git clone https://github.com/anshu968/ddos-protection
cd ddos-protection
chmod +x start.sh
./start.sh

first run befor ./start.sh
nano app.py
# OR manually:
pip3 install -r requirements.txt
python3 app.py
```

Access at: `http://YOUR_VPS_IP:2026`

On first run you will be redirected to the **installation wizard** at `/install`.

---

## 🔑 Installation Wizard

The first time you open the panel, the wizard will guide you through 3 steps:

| Step | What you enter |
|------|----------------|
| **1 — License** | Your license key (see valid keys below) |
| **2 — Admin Account** | Admin email address + admin login password |
| **3 — Security** | Advanced (super admin) password for VPS control |

### ✅ Valid License Keys

```
dm rajveer_6362 to buy the tool price 100 inr permanent tool 
```

> ⚠️ **Each key can be used to install one instance.** Keep your key private.

---

## ✨ Features

### 🔒 Security
- Real-time DDoS detection (tracks requests per minute per IP)
- Auto-block IPs exceeding configurable threshold (default: 100 req/min)
- Manual IP block/unblock with iptables integration
- Full attack log with IP, type, req/min, timestamp

### 📊 Monitoring
- Live CPU, RAM, Disk usage with progress bars
- Network bytes sent/received
- Port 80 service detection (Nginx, Apache, etc.)
- Active IP connection count

### 👥 Users
- Admin + Normal user roles
- Block / Unblock / Promote / Demote users
- Registration system

### 🖥️ VPS Control (Advanced/Super Admin)
- Reboot / Shutdown VPS remotely
- Kill any port instantly (fuser)
- Port forwarding via iptables NAT

### ⚙️ Settings
- Toggle Auto-Protect mode
- Toggle Maintenance mode
- Configurable DDoS threshold
- 4 background themes
- Customizable panel name

---

## 🔧 Configuration

All passwords and settings are set during the installation wizard. The config is stored in `valkas_config.json` (auto-created). To **re-run the wizard**, delete `valkas_config.json` and restart the app.

---

## 🏗️ Tech Stack

- **Backend**: Python 3 + Flask
- **Database**: SQLite (auto-created on first run)
- **Firewall**: iptables (requires root for actual blocking)
- **Monitoring**: psutil
- **Frontend**: Vanilla HTML/CSS/JS (no frameworks needed)

---

## ⚠️ Notes

- Run as root for iptables firewall commands to work
- For production, use `gunicorn`:
  ```bash
  pip3 install gunicorn
  gunicorn -w 4 -b 0.0.0.0:2026 app:app
  ```
- Use a reverse proxy (Nginx) in front for SSL/HTTPS

---

## 📁 File Structure

```
valkas-protection/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── start.sh                  # Setup & run script
├── README.md                 # This file
├── valkas_config.json        # Auto-created after install
├── valkas_protection.db      # Auto-created SQLite database
└── templates/
    ├── install.html              # Installation wizard (step 1-4)
    ├── login.html                # Login / Register page
    ├── admin_dashboard.html      # Full admin panel
    ├── user_dashboard.html       # User stats view
    └── maintenance.html          # Maintenance mode page
```
