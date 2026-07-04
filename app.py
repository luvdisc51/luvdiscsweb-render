import os
import re
import secrets
import sqlite3
import string
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
SITE_DIR = BASE_DIR / "site"

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-this-secret-key")

# For luvdiscsweb.xyz + subdomains, set this to .luvdiscsweb.xyz in Render.
# For local testing, leave it empty.
if os.environ.get("SESSION_COOKIE_DOMAIN"):
    app.config["SESSION_COOKIE_DOMAIN"] = os.environ["SESSION_COOKIE_DOMAIN"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 30
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/luvdiscsweb/app.db"))
VISITOR_COOKIE_NAME = "luv_visitor_id"
VISITOR_COOKIE_DAYS = 365

TIERS = {
    "premium": {
        "name": "Premium",
        "price": "$0.99",
        "rank": 1,
        "benefits": ["Get all premium games."],
    },
    "super_premium": {
        "name": "Super Premium",
        "price": "$2.99",
        "rank": 2,
        "benefits": [
            "All things of previous tiers.",
            "Get my YouTube/linktree.",
            "Be able to friend me on Discord.",
        ],
    },
    "supporter": {
        "name": "Supporter",
        "price": "$4.99",
        "rank": 3,
        "benefits": ["All things of previous tiers.", "Early access to new games.", "Much more!"],
    },
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
VISITOR_RE = re.compile(r"^[a-f0-9]{32}$")
CODE_ALPHABET = string.ascii_uppercase + string.digits


def now_utc():
    return datetime.now(timezone.utc)


def utc_iso(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def add_months(dt, months):
    month = dt.month - 1 + months
    year = dt.year + month // 12
    month = month % 12 + 1
    days_in_month = [
        31,
        29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ]
    day = min(dt.day, days_in_month[month - 1])
    return dt.replace(year=year, month=month, day=day)


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'free',
                expires_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS codes (
                code TEXT PRIMARY KEY,
                tier TEXT NOT NULL,
                months INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                used_by INTEGER,
                used_at TEXT,
                FOREIGN KEY (used_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS visitors (
                visitor_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_hits INTEGER NOT NULL DEFAULT 0,
                last_path TEXT,
                last_host TEXT,
                last_user_agent TEXT,
                linked_user_id INTEGER,
                FOREIGN KEY (linked_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS page_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_id TEXT NOT NULL,
                path TEXT NOT NULL,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                viewed_at TEXT NOT NULL,
                user_agent TEXT,
                user_id INTEGER,
                FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        row = conn.execute("SELECT id FROM admin WHERE id = 1").fetchone()
        if row is None:
            admin_username = os.environ.get("ADMIN_USERNAME", "admin")
            admin_password = os.environ.get("ADMIN_PASSWORD", "ChangeMeNow123!")
            conn.execute(
                "INSERT INTO admin (id, username, password_hash, updated_at) VALUES (1, ?, ?, ?)",
                (admin_username, generate_password_hash(admin_password), utc_iso(now_utc())),
            )


init_db()


def host_name():
    return request.host.split(":")[0].lower()


def is_sub_host():
    host = host_name()
    return host == "sub.luvdiscsweb.xyz" or host.startswith("sub.") or (host in ("localhost", "127.0.0.1") and request.path.startswith("/sub"))


def is_redeem_host():
    host = host_name()
    return host == "redeem.luvdiscsweb.xyz" or host.startswith("redeem.") or (host in ("localhost", "127.0.0.1") and request.path.startswith("/redeem"))


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def active_tier(user):
    if not user or user["tier"] == "free":
        return "free"
    expires = parse_iso(user["expires_at"])
    if not expires or expires < now_utc():
        return "free"
    return user["tier"]


def tier_rank(tier):
    return TIERS.get(tier, {}).get("rank", 0)


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Log in first, then try again.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Admin login needed.")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


def should_track_request():
    if request.endpoint in {"assets"}:
        return False
    if request.path.startswith("/assets/"):
        return False
    if request.path in {"/favicon.ico", "/robots.txt"}:
        return False
    if request.method not in {"GET", "POST"}:
        return False
    return True


@app.before_request
def track_unique_visitor():
    if not should_track_request():
        return

    visitor_id = request.cookies.get(VISITOR_COOKIE_NAME, "").lower()
    if not VISITOR_RE.match(visitor_id):
        visitor_id = secrets.token_hex(16)
        g.set_visitor_cookie = visitor_id
    g.visitor_id = visitor_id

    # This should never break the website. If analytics has a problem, pages still load.
    try:
        at = utc_iso(now_utc())
        ua = (request.headers.get("User-Agent") or "")[:500]
        path = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path
        user_id = session.get("user_id")
        with db() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO visitors
                (visitor_id, first_seen, last_seen, total_hits, last_path, last_host, last_user_agent, linked_user_id)
                VALUES (?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (visitor_id, at, at, path, host_name(), ua, user_id),
            )
            conn.execute(
                """
                UPDATE visitors
                SET last_seen = ?,
                    total_hits = total_hits + 1,
                    last_path = ?,
                    last_host = ?,
                    last_user_agent = ?,
                    linked_user_id = COALESCE(?, linked_user_id)
                WHERE visitor_id = ?
                """,
                (at, path, host_name(), ua, user_id, visitor_id),
            )
            conn.execute(
                """
                INSERT INTO page_views (visitor_id, path, host, method, viewed_at, user_agent, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (visitor_id, path, host_name(), request.method, at, ua, user_id),
            )
    except Exception:
        pass


@app.after_request
def set_tracking_cookie(response):
    visitor_id = getattr(g, "set_visitor_cookie", None)
    if visitor_id:
        cookie_domain = app.config.get("SESSION_COOKIE_DOMAIN")
        response.set_cookie(
            VISITOR_COOKIE_NAME,
            visitor_id,
            max_age=60 * 60 * 24 * VISITOR_COOKIE_DAYS,
            httponly=True,
            samesite="Lax",
            secure=request.scheme == "https",
            domain=cookie_domain,
        )
    return response


def render_page(title, body, wide=False):
    user = current_user()
    admin_logged_in = bool(session.get("admin_id"))
    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{ title }}</title>
            <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.png">
            <style>
                :root { font-family: Arial, sans-serif; color: #1f2937; background: #f7f7fb; }
                body { margin: 0; }
                header { background: #ffffff; border-bottom: 1px solid #e5e7eb; padding: 14px 18px; display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
                header a { color: #2563eb; text-decoration: none; font-weight: 700; }
                main { max-width: {{ '1100px' if wide else '760px' }}; margin: 28px auto; padding: 0 18px; }
                .card { background: white; border: 1px solid #e5e7eb; border-radius: 16px; padding: 20px; box-shadow: 0 8px 25px rgba(0,0,0,.06); margin: 14px 0; }
                .tiers { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 16px; }
                .tier { display: flex; flex-direction: column; justify-content: space-between; }
                .price { font-size: 34px; font-weight: 900; margin: 8px 0; }
                .statgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
                .stat { background: #eef2ff; border-radius: 14px; padding: 14px; }
                .stat strong { font-size: 30px; display: block; }
                button, .button, input, select { font: inherit; }
                button, .button { background: #2563eb; color: white; border: 0; border-radius: 10px; padding: 10px 14px; cursor: pointer; text-decoration: none; display: inline-block; font-weight: 700; margin-top: 8px; }
                button.secondary, .button.secondary { background: #4b5563; }
                button.danger, .button.danger { background: #dc2626; }
                button.disabled, .button.disabled { background: #9ca3af; cursor: not-allowed; }
                input, select { width: 100%; box-sizing: border-box; padding: 10px; margin: 6px 0 12px; border-radius: 10px; border: 1px solid #cbd5e1; }
                label { font-weight: 700; }
                table { border-collapse: collapse; width: 100%; background: white; }
                th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
                code { background: #eef2ff; padding: 3px 6px; border-radius: 6px; font-weight: 700; }
                .flash { background: #fff7ed; border: 1px solid #fed7aa; padding: 12px; border-radius: 12px; margin: 12px 0; }
                .ok { background: #ecfdf5; border: 1px solid #86efac; }
                .muted { color: #6b7280; }
            </style>
        </head>
        <body>
            <header>
                <a href="https://luvdiscsweb.xyz">LuvdiscsWeb</a>
                <a href="https://sub.luvdiscsweb.xyz">Subscriptions</a>
                <a href="https://redeem.luvdiscsweb.xyz">Redeem</a>
                <span style="flex: 1"></span>
                {% if user %}
                    <span>Signed in as <strong>{{ user['username'] }}</strong></span>
                    <a href="{{ url_for('account') }}">Account</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                {% else %}
                    <a href="{{ url_for('login') }}">Login</a>
                    <a href="{{ url_for('signup') }}">Signup</a>
                {% endif %}
                {% if admin_logged_in %}
                    <a href="{{ url_for('admin_dashboard') }}">Admin</a>
                {% endif %}
            </header>
            <main>
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <div class="flash">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                {{ body|safe }}
            </main>
        </body>
        </html>
        """,
        title=title,
        body=body,
        user=user,
        admin_logged_in=admin_logged_in,
        wide=wide,
    )


@app.route("/")
def home():
    if is_redeem_host():
        return redeem_home()
    if is_sub_host():
        return subscribe_home()
    return send_from_directory(SITE_DIR, "index.html")


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(SITE_DIR / "assets", filename)


@app.route("/<path:filename>")
def site_file(filename):
    allowed = {"index.html", "index.js", "games.html", "games.js", "cookie.html", "cookie.js"}
    if filename in allowed:
        return send_from_directory(SITE_DIR, filename)
    abort(404)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            flash("Username must be 3-30 characters and only use letters, numbers, and underscores.")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.")
        else:
            try:
                with db() as conn:
                    cur = conn.execute(
                        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), utc_iso(now_utc())),
                    )
                    session.permanent = True
                    session["user_id"] = cur.lastrowid
                flash("Signup complete!")
                return redirect(url_for("account"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.")
    return render_page(
        "Signup",
        """
        <div class="card">
            <h1>Signup</h1>
            <form method="post">
                <label>Username</label>
                <input name="username" autocomplete="username" required>
                <label>Password</label>
                <input name="password" type="password" autocomplete="new-password" required>
                <button>Create account</button>
            </form>
        </div>
        """,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            flash("Logged in!")
            return redirect(url_for("account"))
        flash("Wrong username or password.")
    return render_page(
        "Login",
        """
        <div class="card">
            <h1>Login</h1>
            <form method="post">
                <label>Username</label>
                <input name="username" autocomplete="username" required>
                <label>Password</label>
                <input name="password" type="password" autocomplete="current-password" required>
                <button>Login</button>
            </form>
        </div>
        """,
    )


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out.")
    return redirect(url_for("home"))


@app.route("/account")
@require_login
def account():
    user = current_user()
    tier = active_tier(user)
    expires = user["expires_at"] or "No active plan"
    body = f"""
    <div class="card">
        <h1>Your account</h1>
        <p><strong>Username:</strong> {escape(user['username'])}</p>
        <p><strong>Active tier:</strong> {tier.replace('_', ' ').title()}</p>
        <p><strong>Expires:</strong> {escape(expires)}</p>
        <a class="button" href="{url_for('subscribe_home')}">View plans</a>
        <a class="button secondary" href="{url_for('redeem_home')}">Redeem a code</a>
    </div>
    <div class="card">
        <h2>Premium stuff</h2>
        <p><a href="{url_for('premium_games')}">Premium games</a></p>
        <p><a href="{url_for('super_premium_links')}">Super Premium links</a></p>
        <p><a href="{url_for('supporter_area')}">Supporter early access</a></p>
    </div>
    """
    return render_page("Account", body)


@app.route("/subscribe")
def subscribe_home():
    cards = []
    for key, tier in TIERS.items():
        benefits = "".join(f"<li>{escape(b)}</li>" for b in tier["benefits"])
        cards.append(
            f"""
            <div class="card tier">
                <div>
                    <h2>{escape(tier['name'])}</h2>
                    <div class="price">{escape(tier['price'])}</div>
                    <p class="muted">PayPal is turned off for now. Use an admin-generated redeem code to activate this tier.</p>
                    <ul>{benefits}</ul>
                </div>
                <a class="button" href="{url_for('redeem_home')}">Redeem code</a>
            </div>
            """
        )
    body = f"""
    <h1>LuvdiscsWeb Pro</h1>
    <p class="muted">PayPal is currently disabled. Codes still work, so you can activate users from the admin panel.</p>
    <div class="tiers">{''.join(cards)}</div>
    <div class="card">
        <h2>Need an account?</h2>
        <p>Signup or login, then redeem a 20-character code.</p>
        <a class="button" href="{url_for('signup')}">Signup</a>
        <a class="button secondary" href="{url_for('login')}">Login</a>
    </div>
    """
    return render_page("LuvdiscsWeb Pro", body, wide=True)


@app.route("/redeem", methods=["GET", "POST"])
def redeem_home():
    user = current_user()
    if request.method == "POST":
        if not user:
            flash("Log in before redeeming a code.")
            return redirect(url_for("login"))
        code = request.form.get("code", "").strip().upper().replace("-", "")
        with db() as conn:
            row = conn.execute("SELECT * FROM codes WHERE code = ?", (code,)).fetchone()
            if not row:
                flash("That code does not exist.")
                return redirect(url_for("redeem_home"))
            if row["used_by"]:
                flash("That code was already used.")
                return redirect(url_for("redeem_home"))
            months = int(row["months"])
            new_tier, new_expiry = activate_user_plan(conn, user["id"], row["tier"], months)
            conn.execute(
                "UPDATE codes SET used_by = ?, used_at = ? WHERE code = ?",
                (user["id"], utc_iso(now_utc()), code),
            )
        flash(f"Code redeemed! Your account now has {new_tier.replace('_', ' ').title()} until {utc_iso(new_expiry)}.")
        return redirect(url_for("account"))
    login_note = "" if user else "<p class='muted'>You need to login or signup before redeeming.</p>"
    body = f"""
    <div class="card">
        <h1>Redeem a Pro code</h1>
        {login_note}
        <form method="post">
            <label>20-character code</label>
            <input name="code" maxlength="24" placeholder="ABCD1234EFGH5678IJKL" required>
            <button>Redeem</button>
        </form>
    </div>
    """
    return render_page("Redeem", body)


def activate_user_plan(conn, user_id, tier_key, months):
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise RuntimeError("User for this code no longer exists.")
    start = parse_iso(user["expires_at"]) if user["expires_at"] else None
    if not start or start < now_utc():
        start = now_utc()
    new_expiry = add_months(start, months)
    current = active_tier(user)
    new_tier = tier_key if tier_rank(tier_key) >= tier_rank(current) else current
    conn.execute("UPDATE users SET tier = ?, expires_at = ? WHERE id = ?", (new_tier, utc_iso(new_expiry), user_id))
    return new_tier, new_expiry


def require_tier(required):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Log in first.")
                return redirect(url_for("login"))
            if tier_rank(active_tier(user)) < tier_rank(required):
                flash(f"You need {TIERS[required]['name']} or higher for that page.")
                return redirect(url_for("subscribe_home"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.route("/premium-games")
@require_tier("premium")
def premium_games():
    body = """
    <div class="card">
        <h1>Premium games</h1>
        <p>Put your premium game links here.</p>
    </div>
    """
    return render_page("Premium games", body)


@app.route("/super-premium-links")
@require_tier("super_premium")
def super_premium_links():
    linktree_url = os.environ.get("LINKTREE_URL", "").strip()
    discord_info = os.environ.get("DISCORD_FRIEND_INFO", "Set DISCORD_FRIEND_INFO in Render to show your Discord friend info here.")
    link_html = f'<p><a class="button" href="{escape(linktree_url)}">Open YouTube / Linktree</a></p>' if linktree_url else "<p>Set LINKTREE_URL in Render to show the YouTube/linktree button here.</p>"
    body = f"""
    <div class="card">
        <h1>Super Premium</h1>
        {link_html}
        <p><strong>Discord friend info:</strong> {escape(discord_info)}</p>
    </div>
    """
    return render_page("Super Premium", body)


@app.route("/supporter")
@require_tier("supporter")
def supporter_area():
    body = """
    <div class="card">
        <h1>Supporter</h1>
        <p>Early access to new games.</p>
        <p>Much more!</p>
    </div>
    """
    return render_page("Supporter", body)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            admin = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
        if admin and admin["username"] == username and check_password_hash(admin["password_hash"], password):
            session.permanent = True
            session["admin_id"] = 1
            flash("Admin logged in.")
            return redirect(url_for("admin_dashboard"))
        flash("Wrong admin username or password.")
    return render_page(
        "Admin Login",
        """
        <div class="card">
            <h1>Admin login</h1>
            <form method="post">
                <label>Admin username</label>
                <input name="username" autocomplete="username" required>
                <label>Admin password</label>
                <input name="password" type="password" autocomplete="current-password" required>
                <button>Login</button>
            </form>
        </div>
        """,
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    flash("Admin logged out.")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@require_admin
def admin_dashboard():
    today_start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    with db() as conn:
        users = conn.execute("SELECT id, username, tier, expires_at, created_at FROM users ORDER BY id DESC LIMIT 25").fetchall()
        codes = conn.execute(
            """
            SELECT codes.*, users.username AS used_username
            FROM codes LEFT JOIN users ON users.id = codes.used_by
            ORDER BY codes.created_at DESC LIMIT 25
            """
        ).fetchall()
        total_visitors = conn.execute("SELECT COUNT(*) AS c FROM visitors").fetchone()["c"]
        total_views = conn.execute("SELECT COUNT(*) AS c FROM page_views").fetchone()["c"]
        today_visitors = conn.execute("SELECT COUNT(*) AS c FROM visitors WHERE last_seen >= ?", (utc_iso(today_start),)).fetchone()["c"]
        today_views = conn.execute("SELECT COUNT(*) AS c FROM page_views WHERE viewed_at >= ?", (utc_iso(today_start),)).fetchone()["c"]
        recent_views = conn.execute(
            """
            SELECT page_views.*, users.username AS username
            FROM page_views LEFT JOIN users ON users.id = page_views.user_id
            ORDER BY page_views.id DESC LIMIT 12
            """
        ).fetchall()
    user_rows = "".join(
        f"<tr><td>{escape(u['username'])}</td><td>{escape(u['tier'])}</td><td>{escape(u['expires_at'] or '')}</td><td>{escape(u['created_at'])}</td></tr>" for u in users
    ) or "<tr><td colspan='4'>No users yet.</td></tr>"
    code_rows = "".join(
        f"<tr><td><code>{escape(c['code'])}</code></td><td>{escape(TIERS[c['tier']]['name'])}</td><td>{c['months']}</td><td>{escape(c['used_username'] or '')}</td><td>{escape(c['used_at'] or '')}</td></tr>" for c in codes
    ) or "<tr><td colspan='5'>No codes yet.</td></tr>"
    recent_rows = "".join(
        f"<tr><td><code>{escape(v['visitor_id'][:8])}</code></td><td>{escape(v['host'])}</td><td>{escape(v['path'])}</td><td>{escape(v['username'] or '')}</td><td>{escape(v['viewed_at'])}</td></tr>" for v in recent_views
    ) or "<tr><td colspan='5'>No visits yet.</td></tr>"
    body = f"""
    <div class="card">
        <h1>Admin dashboard</h1>
        <a class="button" href="{url_for('admin_generate')}">Generate codes</a>
        <a class="button secondary" href="{url_for('admin_visitors')}">Visitor analytics</a>
        <a class="button secondary" href="{url_for('admin_settings')}">Change admin username/password</a>
        <a class="button secondary" href="{url_for('admin_logout')}">Admin logout</a>
    </div>
    <div class="card">
        <h2>Website traffic</h2>
        <div class="statgrid">
            <div class="stat"><strong>{total_visitors}</strong>Total unique visitors</div>
            <div class="stat"><strong>{total_views}</strong>Total page views</div>
            <div class="stat"><strong>{today_visitors}</strong>Unique visitors today</div>
            <div class="stat"><strong>{today_views}</strong>Page views today</div>
        </div>
    </div>
    <div class="card">
        <h2>Recent page visits</h2>
        <table><tr><th>Visitor</th><th>Host</th><th>Path</th><th>Logged-in user</th><th>Time</th></tr>{recent_rows}</table>
    </div>
    <div class="card">
        <h2>Newest users</h2>
        <table><tr><th>Username</th><th>Tier</th><th>Expires</th><th>Created</th></tr>{user_rows}</table>
    </div>
    <div class="card">
        <h2>Newest codes</h2>
        <table><tr><th>Code</th><th>Tier</th><th>Months</th><th>Used by</th><th>Used at</th></tr>{code_rows}</table>
    </div>
    """
    return render_page("Admin", body, wide=True)


@app.route("/admin/visitors")
@require_admin
def admin_visitors():
    with db() as conn:
        top_pages = conn.execute(
            """
            SELECT path, COUNT(*) AS views, COUNT(DISTINCT visitor_id) AS unique_visitors
            FROM page_views
            GROUP BY path
            ORDER BY views DESC
            LIMIT 20
            """
        ).fetchall()
        recent_visitors = conn.execute(
            """
            SELECT visitors.*, users.username AS username
            FROM visitors LEFT JOIN users ON users.id = visitors.linked_user_id
            ORDER BY visitors.last_seen DESC LIMIT 30
            """
        ).fetchall()
    top_rows = "".join(
        f"<tr><td>{escape(p['path'])}</td><td>{p['views']}</td><td>{p['unique_visitors']}</td></tr>" for p in top_pages
    ) or "<tr><td colspan='3'>No page views yet.</td></tr>"
    visitor_rows = "".join(
        f"<tr><td><code>{escape(v['visitor_id'][:8])}</code></td><td>{v['total_hits']}</td><td>{escape(v['last_host'] or '')}</td><td>{escape(v['last_path'] or '')}</td><td>{escape(v['username'] or '')}</td><td>{escape(v['first_seen'])}</td><td>{escape(v['last_seen'])}</td></tr>" for v in recent_visitors
    ) or "<tr><td colspan='7'>No visitors yet.</td></tr>"
    body = f"""
    <div class="card">
        <h1>Visitor analytics</h1>
        <p class="muted">Unique visitors are counted with an anonymous browser cookie named <code>{VISITOR_COOKIE_NAME}</code>. It works across your main domain, subdomain, and redeem domain when <code>SESSION_COOKIE_DOMAIN=.luvdiscsweb.xyz</code> is set.</p>
        <a class="button secondary" href="{url_for('admin_dashboard')}">Back to admin</a>
    </div>
    <div class="card">
        <h2>Top pages</h2>
        <table><tr><th>Page</th><th>Views</th><th>Unique visitors</th></tr>{top_rows}</table>
    </div>
    <div class="card">
        <h2>Recent unique visitors</h2>
        <table><tr><th>Visitor</th><th>Total hits</th><th>Last host</th><th>Last path</th><th>Linked user</th><th>First seen</th><th>Last seen</th></tr>{visitor_rows}</table>
    </div>
    """
    return render_page("Visitor analytics", body, wide=True)


@app.route("/admin/generate", methods=["GET", "POST"])
@require_admin
def admin_generate():
    generated = []
    if request.method == "POST":
        tier = request.form.get("tier", "")
        try:
            months = int(request.form.get("months", "0"))
            amount = int(request.form.get("amount", "1"))
        except ValueError:
            months = 0
            amount = 0
        if tier not in TIERS:
            flash("Pick a real tier.")
        elif not (1 <= months <= 1188):
            flash("Months must be from 1 to 1188.")
        elif not (1 <= amount <= 100):
            flash("Amount must be from 1 to 100.")
        else:
            with db() as conn:
                while len(generated) < amount:
                    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(20))
                    try:
                        conn.execute(
                            "INSERT INTO codes (code, tier, months, created_at) VALUES (?, ?, ?, ?)",
                            (code, tier, months, utc_iso(now_utc())),
                        )
                        generated.append(code)
                    except sqlite3.IntegrityError:
                        pass
            flash(f"Generated {len(generated)} code(s).")
    code_html = ""
    if generated:
        code_html = "<div class='card ok'><h2>New codes</h2>" + "".join(f"<p><code>{c}</code></p>" for c in generated) + "</div>"
    options = "".join(f"<option value='{key}'>{escape(tier['name'])}</option>" for key, tier in TIERS.items())
    body = f"""
    {code_html}
    <div class="card">
        <h1>Generate redeem codes</h1>
        <form method="post">
            <label>Tier</label>
            <select name="tier">{options}</select>
            <label>Months, 1 to 1188</label>
            <input name="months" type="number" min="1" max="1188" value="1" required>
            <label>How many codes, 1 to 100</label>
            <input name="amount" type="number" min="1" max="100" value="1" required>
            <button>Generate 20-character code(s)</button>
        </form>
        <p><a href="{url_for('admin_dashboard')}">Back to admin</a></p>
    </div>
    """
    return render_page("Generate codes", body)


@app.route("/admin/settings", methods=["GET", "POST"])
@require_admin
def admin_settings():
    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "")
        if not USERNAME_RE.match(new_username):
            flash("Admin username must be 3-30 characters and only use letters, numbers, and underscores.")
        elif new_password and len(new_password) < 8:
            flash("New admin password must be at least 8 characters.")
        else:
            with db() as conn:
                if new_password:
                    conn.execute(
                        "UPDATE admin SET username = ?, password_hash = ?, updated_at = ? WHERE id = 1",
                        (new_username, generate_password_hash(new_password), utc_iso(now_utc())),
                    )
                else:
                    conn.execute(
                        "UPDATE admin SET username = ?, updated_at = ? WHERE id = 1",
                        (new_username, utc_iso(now_utc())),
                    )
            flash("Admin settings updated.")
            return redirect(url_for("admin_dashboard"))
    with db() as conn:
        admin = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
    body = f"""
    <div class="card">
        <h1>Admin settings</h1>
        <form method="post">
            <label>Admin username</label>
            <input name="username" value="{escape(admin['username'])}" required>
            <label>New admin password</label>
            <input name="password" type="password" placeholder="Leave blank to keep current password">
            <button>Save admin login</button>
        </form>
        <p><a href="{url_for('admin_dashboard')}">Back to admin</a></p>
    </div>
    """
    return render_page("Admin settings", body)


@app.errorhandler(404)
def not_found(_):
    return render_page("Not found", "<div class='card'><h1>404</h1><p>That page was not found.</p></div>"), 404


if __name__ == "__main__":
    app.run(debug=True)
