from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3, hashlib, os, subprocess, psutil, time, threading, json
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(32)

PANEL_NAME = "Valkas Protection"
DB_PATH = "valkas_protection.db"
CONFIG_PATH = "valkas_config.json"

# Valid license keys
VALID_LICENSES = [
    "purchaseingfromrajveerpremanenttool",
    "thanksforusemadebynissalop2",
    "paidlicense67111",
    "567-license#hfj",
    "nissal-rajjver-tnx"
]

# In-memory traffic tracking
ip_request_counts = defaultdict(list)   # ip -> [timestamps]
ip_warn_count     = defaultdict(int)    # ip -> how many times near threshold
blocked_ips_cache = set()
ddos_threshold = 100    # requests per minute — mirrors panel setting
auto_protect   = True
maintenance_mode = False
current_theme  = "stars"
_track_lock    = threading.Lock()

# Auto-clean stale IP data every 5 minutes so RAM doesn't grow forever
def _cleanup_tracker():
    while True:
        time.sleep(300)
        cutoff = time.time() - 120
        with _track_lock:
            stale = [ip for ip, ts in ip_request_counts.items() if not ts or ts[-1] < cutoff]
            for ip in stale:
                del ip_request_counts[ip]
                ip_warn_count.pop(ip, None)

threading.Thread(target=_cleanup_tracker, daemon=True).start()

# Runtime config (loaded from file after install)
ADMIN_PASSWORD = ""
installed = False

# ─── CONFIG FILE ─────────────────────────────────────────────────────────────

def load_config():
    global ADMIN_PASSWORD, installed
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        ADMIN_PASSWORD = cfg.get("advanced_password", "")
        installed = cfg.get("installed", False)
        return cfg
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f)

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(admin_email, admin_password):
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                blocked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                reason TEXT,
                blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
                auto_blocked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS attack_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                attack_type TEXT,
                requests_per_min INTEGER,
                blocked INTEGER DEFAULT 0,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        """)
        db.execute(
            "INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, 'admin')",
            ("admin", hash_pw(admin_password), admin_email)
        )
    print("[Valkas Protection] Database initialized.")

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def get_real_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def is_ip_blocked(ip):
    with get_db() as db:
        row = db.execute("SELECT id FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    return row is not None

def block_ip_db(ip, reason="Manual", auto=False):
    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO blocked_ips (ip,reason,auto_blocked) VALUES (?,?,?)",
                   (ip, reason, 1 if auto else 0))
    blocked_ips_cache.add(ip)
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

def unblock_ip_db(ip):
    with get_db() as db:
        db.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    blocked_ips_cache.discard(ip)
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

def track_request(ip):
    """Track requests in the last 60 seconds for this IP. Thread-safe."""
    now = time.time()
    with _track_lock:
        ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < 60]
        ip_request_counts[ip].append(now)
        return len(ip_request_counts[ip])

def get_ip_rpm(ip):
    """Return current requests/min for an IP without adding a new request."""
    now = time.time()
    with _track_lock:
        return len([t for t in ip_request_counts.get(ip, []) if now - t < 60])

def classify_attack(rpm, threshold):
    """Return attack type label based on how far over threshold the IP is."""
    ratio = rpm / max(threshold, 1)
    if ratio >= 10:
        return "DDoS Flood (Critical)"
    if ratio >= 5:
        return "DDoS Flood (Heavy)"
    if ratio >= 2:
        return "DDoS Flood (Moderate)"
    return "Rate Limit Exceeded"

def log_attack(ip, attack_type, rpm, blocked):
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO attack_log (ip,attack_type,requests_per_min,blocked) VALUES (?,?,?,?)",
                (ip, attack_type, rpm, blocked)
            )
    except Exception:
        pass

# ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

@app.before_request
def check_installed():
    global installed
    cfg = load_config()
    installed = cfg.get("installed", False)

    if request.path.startswith("/install") or request.path.startswith("/static"):
        return

    if not installed:
        return redirect("/install")

@app.before_request
def ddos_check():
    global maintenance_mode
    if not installed:
        return

    # Skip tracking for install/static routes
    if request.path.startswith("/install") or request.path.startswith("/static"):
        return

    if maintenance_mode and session.get("role") != "admin":
        return render_template("maintenance.html", panel_name=PANEL_NAME), 503

    ip = get_real_ip()

    # Fast cache check first (no DB hit)
    if ip in blocked_ips_cache:
        return jsonify({"error": "Your IP is blocked.", "ip": ip}), 403

    # DB check (catches IPs blocked while server was down)
    if is_ip_blocked(ip):
        blocked_ips_cache.add(ip)
        return jsonify({"error": "Your IP is blocked.", "ip": ip}), 403

    if not auto_protect:
        return

    # Count this request and check against panel threshold
    rpm = track_request(ip)

    if rpm > ddos_threshold:
        attack_type = classify_attack(rpm, ddos_threshold)
        block_ip_db(ip, f"Auto-blocked: {rpm} req/min (threshold: {ddos_threshold})", auto=True)
        log_attack(ip, attack_type, rpm, 1)
        return jsonify({
            "error": "Too many requests — IP blocked automatically.",
            "ip": ip,
            "rpm": rpm,
            "threshold": ddos_threshold
        }), 429

    # Warn zone: 80% of threshold — log but don't block yet
    warn_threshold = max(1, int(ddos_threshold * 0.8))
    if rpm >= warn_threshold:
        ip_warn_count[ip] += 1
        # Log warning only once per IP (first time it enters warn zone)
        if ip_warn_count[ip] == 1:
            log_attack(ip, "Warning: High Request Rate", rpm, 0)

# ─── INSTALL WIZARD ──────────────────────────────────────────────────────────

@app.route("/install")
def install_page():
    cfg = load_config()
    if cfg.get("installed"):
        return redirect("/")
    return render_template("install.html", panel_name=PANEL_NAME)

@app.route("/install/verify-license", methods=["POST"])
def install_verify_license():
    data = request.get_json()
    key = data.get("license_key", "").strip()
    if key in VALID_LICENSES:
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid license key. Please check and try again."})

@app.route("/install/complete", methods=["POST"])
def install_complete():
    data = request.get_json()
    license_key = data.get("license_key", "").strip()
    admin_email = data.get("admin_email", "").strip()
    admin_password = data.get("admin_password", "")
    advanced_password = data.get("advanced_password", "")

    if license_key not in VALID_LICENSES:
        return jsonify({"success": False, "message": "Invalid license key."})
    if not admin_email or "@" not in admin_email:
        return jsonify({"success": False, "message": "Valid admin email required."})
    if len(admin_password) < 6:
        return jsonify({"success": False, "message": "Admin password must be at least 6 characters."})
    if len(advanced_password) < 6:
        return jsonify({"success": False, "message": "Advanced password must be at least 6 characters."})

    init_db(admin_email, admin_password)

    cfg = {
        "installed": True,
        "license_key": license_key,
        "admin_email": admin_email,
        "admin_password_hash": hash_pw(admin_password),
        "advanced_password": advanced_password,
        "installed_at": datetime.now().isoformat()
    }
    save_config(cfg)

    global ADMIN_PASSWORD, installed
    ADMIN_PASSWORD = advanced_password
    installed = True

    return jsonify({"success": True})

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect("/admin")
        return redirect("/dashboard")
    return render_template("login.html", panel_name=PANEL_NAME, theme=current_theme)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = hash_pw(data.get("password", ""))
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                          (username, password)).fetchone()
    if not user:
        return jsonify({"success": False, "message": "Invalid credentials."})
    if user["blocked"]:
        return jsonify({"success": False, "message": "Your account is blocked."})
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"success": True, "role": user["role"]})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if len(username) < 3 or len(password) < 6:
        return jsonify({"success": False, "message": "Username ≥3 chars, password ≥6 chars."})
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username,password) VALUES (?,?)",
                       (username, hash_pw(password)))
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already taken."})

# ─── DASHBOARDS ───────────────────────────────────────────────────────────────

@app.route("/dashboard")
def user_dashboard():
    if "user_id" not in session:
        return redirect("/")
    return render_template("user_dashboard.html",
                           username=session["username"],
                           panel_name=PANEL_NAME,
                           theme=current_theme)

@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect("/")
    return render_template("admin_dashboard.html",
                           username=session["username"],
                           panel_name=PANEL_NAME,
                           theme=current_theme)

# ─── API: STATS ───────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()

    port80_service = "None"
    try:
        for conn in psutil.net_connections():
            if conn.laddr.port == 80 and conn.status == "LISTEN":
                try:
                    proc = psutil.Process(conn.pid)
                    port80_service = proc.name()
                except Exception:
                    port80_service = "Unknown"
                break
    except Exception:
        pass

    with get_db() as db:
        blocked_count = db.execute("SELECT COUNT(*) as c FROM blocked_ips").fetchone()["c"]
        attack_count = db.execute("SELECT COUNT(*) as c FROM attack_log WHERE blocked=1").fetchone()["c"]
        recent_attacks = db.execute(
            "SELECT ip, attack_type, requests_per_min, timestamp FROM attack_log ORDER BY id DESC LIMIT 10"
        ).fetchall()

    # Live traffic table: current req/min per IP vs. panel threshold
    now = time.time()
    with _track_lock:
        live_traffic = []
        for ip, timestamps in ip_request_counts.items():
            rpm = len([t for t in timestamps if now - t < 60])
            if rpm == 0:
                continue
            pct = round((rpm / max(ddos_threshold, 1)) * 100, 1)
            if ip in blocked_ips_cache:
                status = "BLOCKED"
            elif rpm >= ddos_threshold:
                status = "DANGER"
            elif rpm >= int(ddos_threshold * 0.8):
                status = "WARNING"
            else:
                status = "OK"
            live_traffic.append({"ip": ip, "rpm": rpm, "pct": pct, "status": status})
        live_traffic.sort(key=lambda x: x["rpm"], reverse=True)
        live_traffic = live_traffic[:20]

    return jsonify({
        "cpu": cpu,
        "ram_used": round(ram.used / 1024**3, 2),
        "ram_total": round(ram.total / 1024**3, 2),
        "ram_percent": ram.percent,
        "disk_used": round(disk.used / 1024**3, 2),
        "disk_total": round(disk.total / 1024**3, 2),
        "disk_percent": disk.percent,
        "net_sent": round(net.bytes_sent / 1024**2, 2),
        "net_recv": round(net.bytes_recv / 1024**2, 2),
        "blocked_ips": blocked_count,
        "attacks_blocked": attack_count,
        "port80_service": port80_service,
        "auto_protect": auto_protect,
        "ddos_threshold": ddos_threshold,
        "recent_attacks": [dict(r) for r in recent_attacks],
        "active_connections": len(ip_request_counts),
        "live_traffic": live_traffic,
        "uptime": time.time()
    })

# ─── API: IP MANAGEMENT ──────────────────────────────────────────────────────

@app.route("/api/blocked-ips")
def api_blocked_ips():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as db:
        rows = db.execute("SELECT * FROM blocked_ips ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/block-ip", methods=["POST"])
def api_block_ip():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manual block")
    if not ip:
        return jsonify({"success": False, "message": "No IP provided."})
    block_ip_db(ip, reason)
    return jsonify({"success": True})

@app.route("/api/unblock-ip", methods=["POST"])
def api_unblock_ip():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    ip = data.get("ip", "").strip()
    unblock_ip_db(ip)
    return jsonify({"success": True})

# ─── API: USERS ───────────────────────────────────────────────────────────────

@app.route("/api/users")
def api_users():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as db:
        rows = db.execute("SELECT id,username,role,blocked,created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/user-action", methods=["POST"])
def api_user_action():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    uid = data.get("id")
    action = data.get("action")
    with get_db() as db:
        if action == "block":
            db.execute("UPDATE users SET blocked=1 WHERE id=?", (uid,))
        elif action == "unblock":
            db.execute("UPDATE users SET blocked=0 WHERE id=?", (uid,))
        elif action == "promote":
            db.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
        elif action == "demote":
            db.execute("UPDATE users SET role='user' WHERE id=?", (uid,))
        elif action == "delete":
            db.execute("DELETE FROM users WHERE id=?", (uid,))
    return jsonify({"success": True})

# ─── API: ADVANCED ADMIN ─────────────────────────────────────────────────────

@app.route("/api/admin-verify", methods=["POST"])
def api_admin_verify():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    if data.get("password") == ADMIN_PASSWORD:
        session["super_admin"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Wrong advanced password."})

@app.route("/api/vps-action", methods=["POST"])
def api_vps_action():
    if not session.get("super_admin"):
        return jsonify({"error": "Super admin required."}), 403
    data = request.get_json()
    action = data.get("action")
    result = ""
    try:
        if action == "reboot":
            result = "Reboot command sent. (Run: sudo reboot)"
            subprocess.Popen(["sudo", "reboot"])
        elif action == "shutdown":
            result = "Shutdown command sent. (Run: sudo shutdown now)"
            subprocess.Popen(["sudo", "shutdown", "now"])
        elif action == "stop_port":
            port = data.get("port", "")
            out = subprocess.run(["fuser", "-k", f"{port}/tcp"],
                                 capture_output=True, text=True, timeout=10)
            result = f"Port {port} stopped. {out.stdout}"
        elif action == "port_forward":
            src = data.get("src_port", "")
            dst = data.get("dst_port", "")
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                            "-p", "tcp", "--dport", str(src),
                            "-j", "REDIRECT", "--to-port", str(dst)],
                           timeout=10)
            result = f"Forwarding port {src} → {dst}"
        else:
            result = "Unknown action."
    except Exception as e:
        result = f"Error: {str(e)}"
    return jsonify({"success": True, "result": result})

# ─── API: SETTINGS ────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["POST"])
def api_settings():
    global auto_protect, ddos_threshold, maintenance_mode, current_theme, PANEL_NAME
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    if "auto_protect" in data:
        auto_protect = bool(data["auto_protect"])
    if "threshold" in data:
        ddos_threshold = int(data["threshold"])
    if "maintenance" in data:
        maintenance_mode = bool(data["maintenance"])
    if "theme" in data:
        current_theme = data["theme"]
    if "panel_name" in data:
        PANEL_NAME = data["panel_name"]
    return jsonify({"success": True})

@app.route("/api/attack-log")
def api_attack_log():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM attack_log ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_config()
    print("""
╔══════════════════════════════════════════╗
║   VALKAS PROTECTION - VPS Security       ║
║   Running on port 2026                   ║
║   First run: visit /install to setup     ║
╚══════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=2026, debug=False)
