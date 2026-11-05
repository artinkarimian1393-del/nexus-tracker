import os, sqlite3, secrets, ipaddress, json
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, request, redirect, render_template, session, url_for, flash, abort, jsonify

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(APP_DIR, "tracker.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-before-deploying")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            destination TEXT NOT NULL,
            label TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT DEFAULT '',
            clicked_at TEXT NOT NULL,
            consent INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(link_id) REFERENCES links(id)
        )""")
init_db()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def valid_destination(value):
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/")
def home():
    return render_template("home.html", logged=session.get("admin", False))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not ADMIN_PASSWORD:
            flash("ابتدا متغیر محیطی ADMIN_PASSWORD را در هاست تنظیم کن.")
        elif secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        else:
            flash("رمز عبور اشتباه است.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@admin_required
def dashboard():
    with db() as con:
        links = con.execute("""SELECT l.*, COUNT(c.id) AS clicks
            FROM links l LEFT JOIN clicks c ON c.link_id=l.id
            GROUP BY l.id ORDER BY l.id DESC""").fetchall()
        recent = con.execute("""SELECT c.*, l.token, l.label
            FROM clicks c JOIN links l ON l.id=c.link_id
            ORDER BY c.id DESC LIMIT 100""").fetchall()
    return render_template("dashboard.html", links=links, recent=recent)

@app.route("/create", methods=["POST"])
@admin_required
def create_link():
    destination = request.form.get("destination", "").strip()
    label = request.form.get("label", "").strip()[:80]
    if not valid_destination(destination):
        flash("آدرس مقصد باید با http:// یا https:// شروع شود.")
        return redirect(url_for("dashboard"))
    token = secrets.token_urlsafe(9)
    with db() as con:
        con.execute("INSERT INTO links(token,destination,label,created_at) VALUES(?,?,?,?)",
                    (token, destination, label, datetime.now(timezone.utc).isoformat()))
    flash("لینک ساخته شد.")
    return redirect(url_for("dashboard"))

@app.route("/go/<token>", methods=["GET", "POST"])
def go(token):
    with db() as con:
        link = con.execute("SELECT * FROM links WHERE token=?", (token,)).fetchone()
    if not link:
        abort(404)
    if request.method == "GET":
        return render_template("consent.html", link=link)
    if request.form.get("consent") != "yes":
        flash("برای ادامه، باید با ثبت داده‌های اعلام‌شده موافقت کنی.")
        return redirect(url_for("go", token=token))
    # Only record after the visitor actively checks consent and presses Continue.
    # On Render/proxy deployments REMOTE_ADDR may be the proxy; no untrusted forwarded headers are used.
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "")[:500]
    with db() as con:
        con.execute("INSERT INTO clicks(link_id,ip_address,user_agent,clicked_at,consent) VALUES(?,?,?,?,1)",
                    (link["id"], ip, ua, datetime.now(timezone.utc).isoformat()))
    return redirect(link["destination"], code=302)

@app.route("/delete-click/<int:click_id>", methods=["POST"])
@admin_required
def delete_click(click_id):
    with db() as con:
        con.execute("DELETE FROM clicks WHERE id=?", (click_id,))
    return redirect(url_for("dashboard"))

@app.route("/delete-link/<int:link_id>", methods=["POST"])
@admin_required
def delete_link(link_id):
    with db() as con:
        con.execute("DELETE FROM clicks WHERE link_id=?", (link_id,))
        con.execute("DELETE FROM links WHERE id=?", (link_id,))
    return redirect(url_for("dashboard"))

@app.route("/rdap", methods=["GET", "POST"])
@admin_required
def rdap():
    result = None
    query_ip = ""
    error = None
    if request.method == "POST":
        query_ip = request.form.get("ip", "").strip()
        try:
            ipaddress.ip_address(query_ip)
            response = requests.get("https://rdap.org/ip/" + query_ip, timeout=12,
                                    headers={"Accept": "application/rdap+json"})
            response.raise_for_status()
            result = json.dumps(response.json(), ensure_ascii=False, indent=2)
        except ValueError:
            error = "آدرس IP معتبر نیست."
        except requests.RequestException as exc:
            error = "دریافت اطلاعات RDAP ناموفق بود: " + str(exc)
    return render_template("rdap.html", result=result, query_ip=query_ip, error=error)

@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
