from flask import Flask, request, redirect, send_from_directory
import sqlite3
import hashlib
import secrets
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

DB = "minicloud.db"
FILES_FOLDER = "files"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB

os.makedirs(FILES_FOLDER, exist_ok=True)

# ---------- DB ----------
def get_db():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)

def init_db():
    with get_db() as db:
        c = db.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            password TEXT,
            approved INTEGER DEFAULT 0,
            activation_key TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            stored_name TEXT,
            real_name TEXT
        )
        """)

# ---------- UTIL ----------
def sanitize(text):
    return text.replace("<", "").replace(">", "")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key():
    return secrets.token_hex(16)

# ---------- USERS ----------
def create_user(url, password):
    key = generate_key()

    with get_db() as db:
        c = db.cursor()
        c.execute(
            "INSERT INTO users (url, password, activation_key) VALUES (?, ?, ?)",
            (url, hash_password(password), key)
        )
        user_id = c.lastrowid

    link = f"http://127.0.0.1:5000/activate/{user_id}/{key}"

    with open("approve.txt", "a") as f:
        f.write(f"{url}|||{link}\n")

def check_user(url, password):
    with get_db() as db:
        c = db.cursor()
        c.execute("SELECT id, password, approved FROM users WHERE url=?", (url,))
        row = c.fetchone()

    if row:
        if row[1] != hash_password(password):
            return "wrong_pass", None
        if row[2] == 0:
            return "not_approved", None
        return "ok", row[0]

    return "not_exist", None

# ---------- FILES ----------
def save_file(file, user_id):
    if file:
        name = secure_filename(file.filename)

        # tamanho seguro
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        if size > MAX_FILE_SIZE:
            return None

        with get_db() as db:
            c = db.cursor()
            c.execute("SELECT MAX(id) FROM files")
            max_id = c.fetchone()[0]
            file_id = (max_id or 0) + 1

        stored_name = f"{file_id}.bin"
        path = os.path.join(FILES_FOLDER, stored_name)

        file.save(path)

        with get_db() as db:
            c = db.cursor()
            c.execute(
                "INSERT INTO files (user_id, stored_name, real_name) VALUES (?, ?, ?)",
                (user_id, stored_name, name)
            )

        return stored_name

    return None

def load_files(user_id):
    with get_db() as db:
        c = db.cursor()
        c.execute(
            "SELECT stored_name, real_name FROM files WHERE user_id=? ORDER BY id DESC",
            (user_id,)
        )
        return c.fetchall()

# ---------- ROUTES ----------

@app.route("/")
def home():
    return """
    <body style="background:black;color:white;">
    <h1>MiniCloud</h1>
    <a href="/register">➕ Registar</a><br><br>

    <form method="POST" action="/login">
        <input name="url" placeholder="user"><br>
        <input type="password" name="password" placeholder="password"><br>
        <button>Login</button>
    </form>
    </body>
    """

@app.route("/login", methods=["POST"])
def login():
    url = sanitize(request.form.get("url"))
    password = request.form.get("password")

    res, uid = check_user(url, password)

    if res == "ok":
        return redirect(f"/user/{uid}")
    return "Erro login"

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""

    if request.method == "POST":
        url = sanitize(request.form.get("url"))
        password = request.form.get("password")

        if url and password:
            try:
                create_user(url, password)
                msg = "Criado! Aguarda aprovação."
            except:
                msg = "Já existe"

    return f"""
    <body style="background:black;color:white;">
    <h2>Registar</h2>
    <form method="POST">
        <input name="url"><br>
        <input type="password" name="password"><br>
        <button>Registar</button>
    </form>
    <p>{msg}</p>
    </body>
    """

@app.route("/activate/<int:user_id>/<key>")
def activate(user_id, key):
    with get_db() as db:
        c = db.cursor()
        c.execute("SELECT activation_key FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

        if row and row[0] == key:
            c.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
            db.commit()
            return "Conta ativada!"

    return "Link inválido"

@app.route("/user/<int:user_id>", methods=["GET", "POST"])
def user_page(user_id):
    error = ""

    if request.method == "POST":
        url = sanitize(request.form.get("url"))
        password = request.form.get("password")
        file = request.files.get("file")

        res, uid = check_user(url, password)

        if res == "ok" and uid == user_id:
            save_file(file, user_id)
            return redirect(f"/user/{user_id}")
        else:
            error = "Erro autenticação"

    files = load_files(user_id)

    html = f"""
    <body style="background:black;color:white;">
    <h2>MiniCloud - User {user_id}</h2>

    <form method="POST" enctype="multipart/form-data">
        <input name="url"><br>
        <input type="password" name="password"><br>
        <input type="file" name="file"><br>
        <button>Upload</button>
    </form>

    <p>{error}</p>
    <hr>
    """

    for stored, real in files:
        html += f'<a href="/file/{stored}" download="{real}">{real}</a><br>'

    html += "</body>"
    return html

@app.route("/file/<filename>")
def download_file(filename):
    return send_from_directory(FILES_FOLDER, filename, as_attachment=True)

# ---------- START ----------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
