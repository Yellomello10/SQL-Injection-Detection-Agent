"""
Offline SQLite-backed Vulnerable Flask Target API
==================================================
A self-contained version of the vulnerable target API that uses SQLite
(Python stdlib) instead of MySQL. No Docker or external DB needed.

Run directly:
    python target_api/app_sqlite.py

⚠️  INTENTIONALLY VULNERABLE — FOR SECURITY TESTING ONLY.
    Never expose to public networks.
"""
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# SQLite database path — created automatically next to this file
DB_PATH = Path(__file__).parent / "sqli_test.db"

# ──────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Return (and cache on g) a SQLite connection for this request."""
    if "db" not in g:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row          # rows behave like dicts
        conn.execute("PRAGMA journal_mode=WAL") # concurrent read safety
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_unsafe(sql: str) -> list[dict]:
    """
    Execute *sql* WITHOUT parameterization.
    ⚠️  INTENTIONALLY VULNERABLE.
    """
    logger.debug("UNSAFE QUERY: %s", sql)
    db = get_db()
    try:
        cur = db.execute(sql)
        return [dict(row) for row in cur.fetchall()]
    except sqlite3.Error as exc:
        raise exc


def query_safe(sql: str, params: tuple = ()) -> list[dict]:
    """Execute *sql* with parameterized *params*. SAFE."""
    db = get_db()
    cur = db.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


def json_ok(data: Any, status: int = 200):
    return jsonify({"status": "ok", "data": data}), status


def json_err(message: str, status: int = 400):
    return jsonify({"status": "error", "message": message}), status


# ──────────────────────────────────────────────
# Database initialisation
# ──────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL UNIQUE,
    password     TEXT NOT NULL,
    email        TEXT NOT NULL,
    role         TEXT DEFAULT 'user',
    full_name    TEXT,
    created_at   TEXT DEFAULT (datetime('now')),
    last_login   TEXT,
    is_active    INTEGER DEFAULT 1,
    secret_token TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL,
    category    TEXT,
    stock       INTEGER DEFAULT 0,
    sku         TEXT UNIQUE,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    product_id  INTEGER NOT NULL,
    quantity    INTEGER NOT NULL DEFAULT 1,
    status      TEXT DEFAULT 'pending',
    total       REAL,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token       TEXT NOT NULL UNIQUE,
    ip_address  TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

SEED_USERS = [
    ("admin",      "hashed_admin_pass",  "admin@company.com",   "admin",     "Alice Admin",      "TOKEN_ADMIN_SECRET_1"),
    ("john_doe",   "hashed_pass_john",   "john@example.com",    "user",      "John Doe",         "TOKEN_USER_002"),
    ("jane_smith", "hashed_pass_jane",   "jane@example.com",    "user",      "Jane Smith",       "TOKEN_USER_003"),
    ("bob_jones",  "hashed_pass_bob",    "bob@example.com",     "user",      "Bob Jones",        "TOKEN_USER_004"),
    ("mod_user",   "hashed_pass_mod",    "mod@company.com",     "moderator", "Moderator User",   "TOKEN_MOD_005"),
    ("alice_w",    "hashed_pass_alice",  "alice.w@example.com", "user",      "Alice Wonderland", "TOKEN_USER_006"),
    ("charlie_b",  "hashed_pass_charlie","charlie@example.com", "user",      "Charlie Brown",    "TOKEN_USER_007"),
    ("diana_p",    "hashed_pass_diana",  "diana@example.com",   "user",      "Diana Prince",     "TOKEN_USER_008"),
    ("eve_m",      "hashed_pass_eve",    "eve@example.com",     "user",      "Eve Miller",       "TOKEN_USER_009"),
    ("frank_c",    "hashed_pass_frank",  "frank@example.com",   "user",      "Frank Castle",     "TOKEN_USER_010"),
]

SEED_PRODUCTS = [
    ("Gaming Laptop Pro",    "High-performance gaming laptop",          1299.99, "electronics", 15,  "EL-001"),
    ("Wireless Mouse",       "Ergonomic wireless mouse",                  29.99, "electronics", 150, "EL-002"),
    ("Mechanical Keyboard",  "RGB mechanical keyboard",                   89.99, "electronics", 75,  "EL-003"),
    ("4K Monitor",           "27-inch 4K IPS display",                  449.99, "electronics", 30,  "EL-004"),
    ("USB-C Hub",            "7-in-1 USB-C hub",                         39.99, "electronics", 200, "EL-005"),
    ("Noise-Cancel Headset", "Active noise cancelling headphones",      199.99, "electronics", 50,  "EL-006"),
    ("Webcam HD",            "1080p HD webcam with mic",                  79.99, "electronics", 90,  "EL-007"),
    ("SSD 1TB",              "NVMe SSD 1TB storage",                    119.99, "electronics", 120, "EL-008"),
    ("Smart Speaker",        "Voice-enabled smart speaker",               49.99, "home",        60,  "HM-001"),
    ("Desk Lamp",            "LED adjustable desk lamp",                  34.99, "home",        80,  "HM-002"),
    ("Office Chair",         "Ergonomic office chair",                  349.99, "furniture",   20,  "FN-001"),
    ("Standing Desk",        "Height-adjustable standing desk",         599.99, "furniture",   10,  "FN-002"),
    ("Python Book",          "Advanced Python Programming",               49.99, "books",       200, "BK-001"),
    ("Security Handbook",    "Web Application Security Testing",          59.99, "books",       150, "BK-002"),
    ("Docker Guide",         "Docker & Kubernetes in Practice",           44.99, "books",       175, "BK-003"),
    ("Coffee Maker",         "Programmable drip coffee maker",            89.99, "appliances",  40,  "AP-001"),
    ("Air Purifier",         "HEPA air purifier large room",            129.99, "appliances",  25,  "AP-002"),
    ("Fitness Tracker",      "Smart fitness & health tracker",           149.99, "wearables",   55,  "WR-001"),
    ("Wireless Earbuds",     "True wireless earbuds with case",           99.99, "electronics", 110, "EL-009"),
    ("Tablet 10-inch",       "10-inch Android tablet",                  299.99, "electronics", 35,  "EL-010"),
]

SEED_ORDERS = [
    (1, 1,  2, "paid",      59.98),  (2, 3,  1, "shipped",   1299.99),
    (3, 5,  4, "delivered", 449.99), (2, 7,  3, "paid",      89.99),
    (4, 9,  1, "pending",   1299.99),(3, 11, 1, "paid",      349.99),
    (5, 13, 2, "delivered", 99.98),  (1, 15, 1, "shipped",   44.99),
    (6, 2,  1, "paid",      29.99),  (7, 4,  1, "delivered", 449.99),
    (8, 6,  2, "paid",      399.98), (9, 8,  1, "shipped",   119.99),
    (10,10, 3, "delivered", 149.97), (1, 12, 1, "cancelled", 599.99),
    (2, 14, 2, "paid",      119.98), (3, 16, 1, "pending",   89.99),
    (4, 18, 1, "paid",      149.99), (5, 20, 2, "shipped",   599.98),
    (6, 1,  1, "delivered", 1299.99),(7, 3,  1, "paid",      89.99),
    (8, 5,  2, "cancelled", 89.98),  (9, 7,  1, "paid",      79.99),
    (10,9,  3, "delivered", 149.97), (1, 11, 2, "shipped",   699.98),
    (2, 13, 1, "pending",   49.99),  (3, 15, 1, "paid",      44.99),
    (4, 17, 1, "delivered", 129.99), (5, 19, 2, "paid",      199.98),
    (6, 2,  3, "shipped",   89.97),  (7, 4,  1, "paid",      449.99),
]


def init_db() -> None:
    """Create schema and seed data if the DB doesn't already exist."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA_SQL)

        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany(
                "INSERT OR IGNORE INTO users (username,password,email,role,full_name,secret_token) "
                "VALUES (?,?,?,?,?,?)", SEED_USERS
            )
        if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            conn.executemany(
                "INSERT OR IGNORE INTO products (name,description,price,category,stock,sku) "
                "VALUES (?,?,?,?,?,?)", SEED_PRODUCTS
            )
        if conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
            conn.executemany(
                "INSERT OR IGNORE INTO orders (user_id,product_id,quantity,status,total) "
                "VALUES (?,?,?,?,?)", SEED_ORDERS
            )
        conn.commit()
        logger.info("SQLite database ready at %s", DB_PATH)
    finally:
        conn.close()


# ──────────────────────────────────────────────
# Health check
# ──────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return json_ok({"db": "sqlite", "service": "sqli-target-api-local", "db_path": str(DB_PATH)})


# ──────────────────────────────────────────────
# VULNERABLE 1: Classic Error-Based SQLi
# GET /api/users?id=1
# ──────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
def get_users():
    """⚠️  VULNERABLE: id parameter concatenated directly into SQL."""
    user_id = request.args.get("id", "1")
    sql = f"SELECT id, username, email, role, full_name, created_at FROM users WHERE id = {user_id}"
    try:
        rows = query_unsafe(sql)
        return json_ok(rows)
    except sqlite3.Error as exc:
        err_msg = str(exc)
        return jsonify({
            "status": "error",
            "message": f"SQL error: {err_msg}",
            "query": sql,
        }), 500


# ──────────────────────────────────────────────
# VULNERABLE 2: UNION-Based SQLi
# GET /api/products?category=electronics
# ──────────────────────────────────────────────
@app.route("/api/products", methods=["GET"])
def get_products():
    """⚠️  VULNERABLE: category parameter enables UNION injection."""
    category = request.args.get("category", "electronics")
    sql = (
        f"SELECT id, name, description, price, category, stock, sku, created_at "
        f"FROM products WHERE category = '{category}'"
    )
    try:
        rows = query_unsafe(sql)
        return json_ok(rows)
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "message": f"SQL error: {exc}", "query": sql}), 500


# ──────────────────────────────────────────────
# VULNERABLE 3: Auth-Bypass SQLi
# POST /api/login  {username, password}
# ──────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    """⚠️  VULNERABLE: username and password concatenated into SQL."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    sql = (
        f"SELECT id, username, email, role, full_name FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        rows = query_unsafe(sql)
        if rows:
            return json_ok({"authenticated": True, "user": rows[0]})
        return json_err("Invalid credentials", 401)
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "message": f"SQL error: {exc}", "query": sql}), 500


# ──────────────────────────────────────────────
# VULNERABLE 4: Blind Boolean-Based SQLi
# GET /api/orders?user_id=1&status=paid
# ──────────────────────────────────────────────
@app.route("/api/orders", methods=["GET"])
def get_orders():
    """⚠️  VULNERABLE: user_id and status enable blind boolean SQLi."""
    user_id = request.args.get("user_id", "1")
    status  = request.args.get("status", "paid")
    sql = (
        f"SELECT id, user_id, product_id, quantity, status, total, created_at "
        f"FROM orders WHERE user_id = {user_id} AND status = '{status}'"
    )
    try:
        rows = query_unsafe(sql)
        return json_ok(rows)
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "message": f"SQL error: {exc}"}), 500


# ──────────────────────────────────────────────
# VULNERABLE 5: Time-Based Blind SQLi (simulated delay)
# GET /api/search?q=laptop
# ──────────────────────────────────────────────
@app.route("/api/search", methods=["GET"])
def search_products():
    """
    ⚠️  VULNERABLE: q parameter enables SQL injection.
    SQLite doesn't have SLEEP(), so we simulate the delay server-side
    when SLEEP or WAITFOR patterns appear in the payload.
    """
    query = request.args.get("q", "")

    # Simulate SLEEP() for time-based payloads (SQLite doesn't support it natively)
    import re as _re
    sleep_match = _re.search(r"SLEEP\s*\(\s*(\d+)\s*\)", query, _re.I)
    waitfor_match = _re.search(r"WAITFOR\s+DELAY", query, _re.I)
    if sleep_match:
        delay = min(int(sleep_match.group(1)), 6)  # cap at 6s for safety
        logger.info("Simulating SLEEP(%d) for time-based SQLi test", delay)
        time.sleep(delay)
    elif waitfor_match:
        time.sleep(5)

    sql = (
        f"SELECT id, name, description, price, category "
        f"FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    )
    try:
        rows = query_unsafe(sql)
        return json_ok(rows)
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "message": f"SQL error: {exc}"}), 500


# ──────────────────────────────────────────────
# VULNERABLE 6: Stacked Queries SQLi
# GET /api/admin/users?role=admin
# ──────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    """⚠️  VULNERABLE: role parameter allows stacked queries via executescript."""
    role = request.args.get("role", "admin")
    sql = f"SELECT id, username, email, role, full_name, created_at FROM users WHERE role = '{role}'"
    try:
        # SQLite executescript supports multiple statements — intentionally vulnerable
        db = get_db()
        # Use executescript to allow stacked queries
        try:
            db.executescript(f"BEGIN; {sql}; COMMIT;")
        except Exception:
            pass
        rows = query_unsafe(sql)
        return json_ok(rows)
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "message": f"SQL error: {exc}"}), 500


# ──────────────────────────────────────────────
# SAFE ENDPOINT (Control): Parameterized Query
# GET /api/reports?from=2024-01-01
# ──────────────────────────────────────────────
@app.route("/api/reports", methods=["GET"])
def get_reports():
    """✅  SAFE: uses parameterized queries — NOT vulnerable to SQLi."""
    from_date = request.args.get("from", "2024-01-01")
    to_date   = request.args.get("to",   "2099-12-31")
    sql = (
        "SELECT o.id, u.username, p.name AS product, o.quantity, "
        "       o.status, o.total, o.created_at "
        "FROM orders o "
        "JOIN users u    ON o.user_id    = u.id "
        "JOIN products p ON o.product_id = p.id "
        "WHERE o.created_at BETWEEN ? AND ? "
        "ORDER BY o.created_at DESC LIMIT 100"
    )
    try:
        rows = query_safe(sql, (from_date, to_date))
        return json_ok(rows)
    except Exception as exc:
        return json_err(f"Query failed: {exc}", 500)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.getenv("FLASK_PORT", "5000"))
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    logger.warning("⚠️  Starting VULNERABLE Flask API (SQLite) on %s:%d", host, port)
    logger.warning("⚠️  FOR SECURITY TESTING ONLY — DO NOT EXPOSE TO PUBLIC INTERNET ⚠️")
    app.run(host=host, port=port, debug=False, use_reloader=False)
