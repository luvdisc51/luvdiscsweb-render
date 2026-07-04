import os
import sqlite3
import secrets
import string
import calendar
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    session,
    flash,
    g,
    make_response,
    render_template_string,
    get_flashed_messages,
)
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# IMPORTANT:
# On Render free, do NOT use /var/data unless you have disks.
# Set this Render env var:
# DB_PATH=/tmp/luvdiscsweb/luvdiscsweb.db
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/luvdiscsweb/luvdiscsweb.db"))

app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-render")

MAIN_BASE_URL = os.environ.get("MAIN_BASE_URL", "https://luvdiscsweb.xyz").rstrip("/")
XTRA_BASE_URL = os.environ.get("XTRA_BASE_URL", "https://xtra.luvdiscsweb.xyz").rstrip("/")

PLANS = {
    "premium": {
        "name": "Premium",
        "price": "$0.99",
        "description": "Get all premium games.",
    },
    "super_premium": {
        "name": "Super Premium",
        "price": "$2.99",
        "description": "All things of previous tiers AND get my YouTube Linktree and be able to friend me on Discord.",
    },
    "supporter": {
        "name": "Supporter",
        "price": "$4.99",
        "description": "All things of previous tiers, early access to new games, and much more!",
    },
}


def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().replace(microsecond=0).isoformat()


def add_months(dt, months):
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


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
                plan TEXT DEFAULT 'free',
                plan_expires_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL,
                months INTEGER NOT NULL,
                used_by INTEGER,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (used_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS visitors (
                visitor_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                user_agent TEXT,
                ip TEXT
            );

            CREATE TABLE IF NOT EXISTS page_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_id TEXT NOT NULL,
                path TEXT NOT NULL,
                host TEXT,
                viewed_at TEXT NOT NULL,
                FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id)
            );
            """
        )

        existing_admin = conn.execute(
            "SELECT value FROM settings WHERE key = 'admin_username'"
        ).fetchone()

        if not existing_admin:
            default_admin_username = os.environ.get("ADMIN_USERNAME", "admin")
            default_admin_password = os.environ.get("ADMIN_PASSWORD", "change-me-now")

            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("admin_username", default_admin_username),
            )
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("admin_password_hash", generate_password_hash(default_admin_password)),
            )


def get_setting(key, default=None):
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.")
            return redirect("/login")
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Admin login required.")
            return redirect("/admin/login")
        return func(*args, **kwargs)

    return wrapper


def make_code(length=20):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@app.before_request
def before_request():
    if request.endpoint == "static":
        return

    visitor_id = request.cookies.get("visitor_id")
    if not visitor_id:
        visitor_id = secrets.token_hex(16)
        g.new_visitor_id = visitor_id

    user_agent = request.headers.get("User-Agent", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = ip.split(",")[0].strip()
    path = request.path
    host = request.host
    timestamp = now_iso()

    with db() as conn:
        conn.execute(
            """
            INSERT INTO visitors (visitor_id, first_seen, last_seen, user_agent, ip)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(visitor_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                user_agent = excluded.user_agent,
                ip = excluded.ip
            """,
            (visitor_id, timestamp, timestamp, user_agent, ip),
        )
        conn.execute(
            "INSERT INTO page_views (visitor_id, path, host, viewed_at) VALUES (?, ?, ?, ?)",
            (visitor_id, path, host, timestamp),
        )


@app.after_request
def after_request(response):
    if hasattr(g, "new_visitor_id"):
        response.set_cookie(
            "visitor_id",
            g.new_visitor_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax",
        )
    return response


BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - LuvdiscsWeb</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #ffeef8;
            color: #251421;
            margin: 0;
            padding: 0;
        }
        header {
            background: #ff74bd;
            color: white;
            padding: 18px;
            text-align: center;
        }
        nav {
            background: #ffd1e9;
            padding: 12px;
            text-align: center;
        }
        nav a {
            margin: 6px;
            display: inline-block;
            color: #8a0050;
            font-weight: bold;
            text-decoration: none;
        }
        main {
            max-width: 900px;
            margin: 24px auto;
            background: white;
            padding: 24px;
            border-radius: 18px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.12);
        }
        button, .button {
            background: #ff4cad;
            color: white;
            border: none;
            border-radius: 12px;
            padding: 12px 18px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 6px 0;
        }
        button:hover, .button:hover {
            background: #d9007c;
        }
        input, select {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 10px;
            margin: 6px 0 14px 0;
            width: 100%;
            max-width: 420px;
            display: block;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
        }
        .card {
            border: 2px solid #ffd1e9;
            border-radius: 16px;
            padding: 16px;
            background: #fff7fb;
        }
        .message {
            background: #fff0b3;
            padding: 10px;
            border-radius: 10px;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            overflow-wrap: anywhere;
        }
        th, td {
            border-bottom: 1px solid #ffd1e9;
            padding: 8px;
            text-align: left;
        }
        code {
            background: #f4f4f4;
            padding: 2px 5px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
<header>
    <h1>LuvdiscsWeb</h1>
</header>

<nav>
    <a href="{{ main_base }}/">Home</a>
    <a href="{{ xtra_base }}/sub">Buy Pro</a>
    <a href="{{ xtra_base }}/redeem">Redeem Code</a>
    <a href="/login">Login</a>
    <a href="/signup">Signup</a>
    <a href="/account">Account</a>
    <a href="/admin">Admin</a>
</nav>

<main>
    {% for message in messages %}
        <div class="message">{{ message }}</div>
    {% endfor %}

    {{ body|safe }}
</main>
</body>
</html>
"""


def page(title, body, **extra):
    messages = list(get_flashed_messages())
    return render_template_string(
        BASE_HTML,
        title=title,
        body=body,
        messages=messages,
        main_base=MAIN_BASE_URL,
        xtra_base=XTRA_BASE_URL,
        plans=PLANS,
        user=current_user(),
        **extra,
    )


@app.route("/")
def home():
    host = request.host.split(":")[0].lower()
    if host == "xtra.luvdiscsweb.xyz":
        return redirect("/sub")

    body = """
    <h2>Welcome to LuvdiscsWeb!</h2>
    <p>This is a place where you get to see all of Luvdisc's HTML games!</p>

    <p>
        <a class="button" href="{{ xtra_base }}/sub">Buy Pro</a>
    </p>

    <p>
        <a class="button" href="/games">Go to Games</a>
    </p>
    """
    return page("Home", render_template_string(body, xtra_base=XTRA_BASE_URL))


@app.route("/games")
def games():
    body = """
    <h2>Games!</h2>
    <p>Put your game links here.</p>

    <button onclick="location.href='/cookie'">Cookie Clicker</button>
    """
    return page("Games", body)


@app.route("/cookie")
def cookie():
    body = """
    <h2>Cookie Clicker</h2>
    <p>Coming soon!</p>
    """
    return page("Cookie Clicker", body)


@app.route("/sub")
def sub():
    body = """
    <h2>Choose a Plan</h2>
    <p>Payments are not turned on yet. For now, use redeem codes.</p>

    <div class="cards">
        {% for key, plan in plans.items() %}
            <div class="card">
                <h3>{{ plan.name }}</h3>
                <h2>{{ plan.price }}</h2>
                <p>{{ plan.description }}</p>
            </div>
        {% endfor %}
    </div>

    <hr>

    <p>
        <a class="button" href="/signup">Signup</a>
        <a class="button" href="/login">Login</a>
        <a class="button" href="/redeem">Redeem Code</a>
    </p>
    """
    return page("Subscriptions", render_template_string(body, plans=PLANS))


@app.route("/redeem", methods=["GET", "POST"])
@login_required
def redeem():
    user = current_user()

    if request.method == "POST":
        code_input = request.form.get("code", "").strip().upper()

        with db() as conn:
            code_row = conn.execute(
                "SELECT * FROM codes WHERE code = ?",
                (code_input,),
            ).fetchone()

            if not code_row:
                flash("That code does not exist.")
                return redirect("/redeem")

            if code_row["used_by"]:
                flash("That code was already used.")
                return redirect("/redeem")

            current_expiry = parse_dt(user["plan_expires_at"])
            start_date = now_utc()

            if current_expiry and current_expiry > start_date:
                start_date = current_expiry

            new_expiry = add_months(start_date, int(code_row["months"]))

            conn.execute(
                """
                UPDATE users
                SET plan = ?, plan_expires_at = ?
                WHERE id = ?
                """,
                (code_row["plan"], new_expiry.isoformat(), user["id"]),
            )

            conn.execute(
                """
                UPDATE codes
                SET used_by = ?, used_at = ?
                WHERE id = ?
                """,
                (user["id"], now_iso(), code_row["id"]),
            )

        flash("Code redeemed successfully!")
        return redirect("/account")

    body = """
    <h2>Redeem Code</h2>
    <p>Enter your 20-character code here.</p>

    <form method="post">
        <label>Code</label>
        <input name="code" placeholder="ABCD1234EFGH5678IJKL" required>
        <button type="submit">Redeem</button>
    </form>
    """
    return page("Redeem", body)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters.")
            return redirect("/signup")

        if len(password) < 4:
            flash("Password must be at least 4 characters.")
            return redirect("/signup")

        try:
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (username, generate_password_hash(password), now_iso()),
                )
            flash("Account created! You can log in now.")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect("/signup")

    body = """
    <h2>Signup</h2>

    <form method="post">
        <label>Username</label>
        <input name="username" required>

        <label>Password</label>
        <input name="password" type="password" required>

        <button type="submit">Create Account</button>
    </form>
    """
    return page("Signup", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Wrong username or password.")
            return redirect("/login")

        session["user_id"] = user["id"]
        flash("Logged in!")
        return redirect("/account")

    body = """
    <h2>Login</h2>

    <form method="post">
        <label>Username</label>
        <input name="username" required>

        <label>Password</label>
        <input name="password" type="password" required>

        <button type="submit">Login</button>
    </form>
    """
    return page("Login", body)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("admin_logged_in", None)
    flash("Logged out.")
    return redirect("/")


@app.route("/account")
@login_required
def account():
    user = current_user()

    plan_key = user["plan"] or "free"
    plan_name = "Free"

    if plan_key in PLANS:
        plan_name = PLANS[plan_key]["name"]

    expires = user["plan_expires_at"] or "No pro plan yet"

    body = """
    <h2>Your Account</h2>

    <p><b>Username:</b> {{ user.username }}</p>
    <p><b>Plan:</b> {{ plan_name }}</p>
    <p><b>Expires:</b> {{ expires }}</p>

    <p>
        <a class="button" href="/redeem">Redeem Code</a>
        <a class="button" href="/logout">Logout</a>
    </p>
    """
    return page(
        "Account",
        render_template_string(body, user=user, plan_name=plan_name, expires=expires),
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin_username = get_setting("admin_username")
        admin_password_hash = get_setting("admin_password_hash")

        if username == admin_username and check_password_hash(admin_password_hash, password):
            session["admin_logged_in"] = True
            flash("Admin logged in.")
            return redirect("/admin")

        flash("Wrong admin username or password.")
        return redirect("/admin/login")

    body = """
    <h2>Admin Login</h2>

    <form method="post">
        <label>Admin Username</label>
        <input name="username" required>

        <label>Admin Password</label>
        <input name="password" type="password" required>

        <button type="submit">Login as Admin</button>
    </form>
    """
    return page("Admin Login", body)


@app.route("/admin")
@admin_required
def admin():
    with db() as conn:
        users_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        codes_count = conn.execute("SELECT COUNT(*) AS c FROM codes").fetchone()["c"]
        used_codes_count = conn.execute(
            "SELECT COUNT(*) AS c FROM codes WHERE used_by IS NOT NULL"
        ).fetchone()["c"]
        visitors_count = conn.execute("SELECT COUNT(*) AS c FROM visitors").fetchone()["c"]
        page_views_count = conn.execute("SELECT COUNT(*) AS c FROM page_views").fetchone()["c"]

    body = """
    <h2>Admin Panel</h2>

    <div class="cards">
        <div class="card"><h3>Users</h3><p>{{ users_count }}</p></div>
        <div class="card"><h3>Total Codes</h3><p>{{ codes_count }}</p></div>
        <div class="card"><h3>Used Codes</h3><p>{{ used_codes_count }}</p></div>
        <div class="card"><h3>Unique Visitors</h3><p>{{ visitors_count }}</p></div>
        <div class="card"><h3>Page Views</h3><p>{{ page_views_count }}</p></div>
    </div>

    <p>
        <a class="button" href="/admin/codes">Generate Codes</a>
        <a class="button" href="/admin/settings">Change Admin Login</a>
        <a class="button" href="/logout">Logout</a>
    </p>
    """
    return page(
        "Admin",
        render_template_string(
            body,
            users_count=users_count,
            codes_count=codes_count,
            used_codes_count=used_codes_count,
            visitors_count=visitors_count,
            page_views_count=page_views_count,
        ),
    )


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "")

        if len(new_username) < 3:
            flash("Admin username must be at least 3 characters.")
            return redirect("/admin/settings")

        set_setting("admin_username", new_username)

        if new_password:
            if len(new_password) < 4:
                flash("Admin password must be at least 4 characters.")
                return redirect("/admin/settings")
            set_setting("admin_password_hash", generate_password_hash(new_password))

        flash("Admin login updated.")
        return redirect("/admin")

    admin_username = get_setting("admin_username", "admin")

    body = """
    <h2>Change Admin Login</h2>

    <form method="post">
        <label>New Admin Username</label>
        <input name="username" value="{{ admin_username }}" required>

        <label>New Admin Password</label>
        <input name="password" type="password" placeholder="Leave blank to keep current password">

        <button type="submit">Save</button>
    </form>
    """
    return page(
        "Admin Settings",
        render_template_string(body, admin_username=admin_username),
    )


@app.route("/admin/codes", methods=["GET", "POST"])
@admin_required
def admin_codes():
    generated_codes = []

    if request.method == "POST":
        plan = request.form.get("plan")
        months = int(request.form.get("months", "1"))
        amount = int(request.form.get("amount", "1"))

        if plan not in PLANS:
            flash("Invalid plan.")
            return redirect("/admin/codes")

        if months < 1 or months > 1188:
            flash("Months must be between 1 and 1188.")
            return redirect("/admin/codes")

        if amount < 1 or amount > 50:
            flash("Amount must be between 1 and 50.")
            return redirect("/admin/codes")

        with db() as conn:
            for _ in range(amount):
                while True:
                    code = make_code(20)
                    try:
                        conn.execute(
                            """
                            INSERT INTO codes (code, plan, months, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            (code, plan, months, now_iso()),
                        )
                        generated_codes.append(code)
                        break
                    except sqlite3.IntegrityError:
                        continue

        flash(f"Generated {len(generated_codes)} code(s).")

    with db() as conn:
        recent_codes = conn.execute(
            """
            SELECT codes.*, users.username AS used_by_username
            FROM codes
            LEFT JOIN users ON users.id = codes.used_by
            ORDER BY codes.id DESC
            LIMIT 25
            """
        ).fetchall()

    body = """
    <h2>Generate Codes</h2>

    <form method="post">
        <label>Plan</label>
        <select name="plan">
            {% for key, plan in plans.items() %}
                <option value="{{ key }}">{{ plan.name }}</option>
            {% endfor %}
        </select>

        <label>Months, 1 to 1188</label>
        <input name="months" type="number" min="1" max="1188" value="1" required>

        <label>How many codes, 1 to 50</label>
        <input name="amount" type="number" min="1" max="50" value="1" required>

        <button type="submit">Generate</button>
    </form>

    {% if generated_codes %}
        <h3>New Codes</h3>
        <ul>
            {% for code in generated_codes %}
                <li><code>{{ code }}</code></li>
            {% endfor %}
        </ul>
    {% endif %}

    <h3>Recent Codes</h3>
    <table>
        <tr>
            <th>Code</th>
            <th>Plan</th>
            <th>Months</th>
            <th>Used By</th>
        </tr>
        {% for code in recent_codes %}
            <tr>
                <td><code>{{ code.code }}</code></td>
                <td>{{ code.plan }}</td>
                <td>{{ code.months }}</td>
                <td>{{ code.used_by_username or "Not used" }}</td>
            </tr>
        {% endfor %}
    </table>
    """
    return page(
        "Generate Codes",
        render_template_string(
            body,
            generated_codes=generated_codes,
            recent_codes=recent_codes,
            plans=PLANS,
        ),
    )


@app.route("/buy-pro")
def buy_pro():
    return redirect(f"{XTRA_BASE_URL}/sub")


@app.route("/redeem-code")
def redeem_code_redirect():
    return redirect(f"{XTRA_BASE_URL}/redeem")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
