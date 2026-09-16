from flask import Flask, request, redirect, url_for, session, send_file, render_template_string, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import sqlite3
import os
import hashlib

app = Flask(_name_)

# Secret key for secure sessions
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

# Configuration
DATABASE = "question_paper.db"
UPLOAD_FOLDER = "secure_papers"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploaded_by INTEGER,
            upload_time TEXT,
            sha256_hash TEXT,
            status TEXT DEFAULT 'Pending',
            release_time TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            paper_id INTEGER,
            timestamp TEXT
        )
    """)

    # Demo users
    users = [
        ("admin", "admin123", "Admin"),
        ("setter", "setter123", "Question Setter"),
        ("officer", "officer123", "Officer"),
        ("controller", "controller123", "Controller"),
        ("student", "student123", "Candidate")
    ]

    for username, password, role in users:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not existing:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role)
            )

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------

def log_action(action, paper_id=None):
    if "username" not in session:
        return

    conn = get_db()

    conn.execute("""
        INSERT INTO audit_logs
        (username, action, paper_id, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        session["username"],
        action,
        paper_id,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# LOGIN REQUIRED
# ---------------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------
# ROLE CHECK
# ---------------------------------------------------------

def role_required(*roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):

            if "role" not in session:
                return redirect(url_for("login"))

            if session["role"] not in roles:
                return "Access Denied: You are not authorized to perform this action.", 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------
# LOGIN PAGE
# ---------------------------------------------------------

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Question Paper System</title>

    <style>
        body {
            font-family: Arial;
            background: #f2f2f2;
        }

        .box {
            width: 400px;
            margin: 100px auto;
            padding: 30px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 10px #aaa;
        }

        h1 {
            text-align: center;
        }

        input, button {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
        }

        button {
            background: #222;
            color: white;
            border: none;
            cursor: pointer;
        }

        .error {
            color: red;
            text-align: center;
        }
    </style>
</head>

<body>

<div class="box">

<h1>Secure Question Paper System</h1>

{% with messages = get_flashed_messages() %}
    {% for message in messages %}
        <p class="error">{{ message }}</p>
    {% endfor %}
{% endwith %}

<form method="POST">

    <input type="text"
           name="username"
           placeholder="Username"
           required>

    <input type="password"
           name="password"
           placeholder="Password"
           required>

    <button type="submit">
        Login
    </button>

</form>

</div>

</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_action("Successful Login")

            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template_string(LOGIN_HTML)


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>

<head>

<title>Dashboard</title>

<style>

body {
    font-family: Arial;
    margin: 40px;
    background: #f5f5f5;
}

.container {
    background: white;
    padding: 25px;
    border-radius: 10px;
}

a, button {
    padding: 8px 12px;
    text-decoration: none;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

th, td {
    border: 1px solid #ccc;
    padding: 10px;
}

th {
    background: #ddd;
}

</style>

</head>

<body>

<div class="container">

<h1>Secure Question Paper Dashboard</h1>

<p>
Logged in as:
<strong>{{ username }}</strong>
</p>

<p>
Role:
<strong>{{ role }}</strong>
</p>

<a href="/logout">Logout</a>

{% if role in ["Question Setter", "Admin"] %}
<br><br>
<a href="/upload">Upload Question Paper</a>
{% endif %}

{% if role in ["Officer", "Admin"] %}
<br><br>
<a href="/admin/papers">Review Question Papers</a>
{% endif %}

{% if role in ["Controller", "Admin"] %}
<br><br>
<a href="/admin/papers">Control Release</a>
{% endif %}

<h2>Available Question Papers</h2>

<table>

<tr>
    <th>Title</th>
    <th>Status</th>
    <th>Release Time</th>
    <th>Action</th>
</tr>

{% for paper in papers %}

<tr>

<td>{{ paper["title"] }}</td>

<td>{{ paper["status"] }}</td>

<td>{{ paper["release_time"] or "Not Scheduled" }}</td>

<td>

{% if paper["status"] == "Released" %}

<a href="/view/{{ paper['id'] }}">View</a>

<a href="/download/{{ paper['id'] }}">Download</a>

{% else %}

Not Released

{% endif %}

</td>

</tr>

{% endfor %}

</table>

</div>

</body>
</html>
"""


@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    papers = conn.execute("""
        SELECT * FROM papers
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template_string(
        DASHBOARD_HTML,
        username=session["username"],
        role=session["role"],
        papers=papers
    )


# ---------------------------------------------------------
# UPLOAD QUESTION PAPER
# ---------------------------------------------------------

UPLOAD_HTML = """
<!DOCTYPE html>
<html>

<head>

<title>Upload Question Paper</title>

<style>

body {
    font-family: Arial;
    background: #f5f5f5;
}

.box {
    width: 500px;
    margin: 50px auto;
    background: white;
    padding: 30px;
    border-radius: 10px;
}

input, button {
    width: 100%;
    padding: 12px;
    margin: 10px 0;
    box-sizing: border-box;
}

button {
    background: #222;
    color: white;
    border: none;
}

</style>

</head>

<body>

<div class="box">

<h1>Upload Question Paper</h1>

<form method="POST" enctype="multipart/form-data">

<label>Question Paper Title</label>

<input type="text"
       name="title"
       placeholder="Enter paper title"
       required>

<label>Select Question Paper</label>

<input type="file"
       name="paper"
       accept=".pdf"
       required>

<button type="submit">
Upload Securely
</button>

</form>

<br>

<a href="/dashboard">Back to Dashboard</a>

</div>

</body>

</html>
"""


@app.route("/upload", methods=["GET", "POST"])
@login_required
@role_required("Question Setter", "Admin")
def upload():

    if request.method == "POST":

        title = request.form["title"]

        file = request.files.get("paper")

        if not file or file.filename == "":
            return "No file selected."

        if not file.filename.lower().endswith(".pdf"):
            return "Only PDF files are allowed."

        original_name = secure_filename(file.filename)

        # Generate unique storage name
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        stored_name = timestamp + "_" + original_name

        filepath = os.path.join(
            UPLOAD_FOLDER,
            stored_name
        )

        file.save(filepath)

        # SHA-256 integrity hash
        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:

            while True:

                data = f.read(4096)

                if not data:
                    break

                sha256.update(data)

        file_hash = sha256.hexdigest()

        conn = get_db()

        cursor = conn.execute("""
            INSERT INTO papers
            (
                title,
                filename,
                stored_filename,
                uploaded_by,
                upload_time,
                sha256_hash,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            title,
            original_name,
            stored_name,
            session["user_id"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_hash,
            "Pending"
        ))

        paper_id = cursor.lastrowid

        conn.commit()
        conn.close()

        log_action("Question Paper Uploaded", paper_id)

        return redirect(url_for("dashboard"))

    return render_template_string(UPLOAD_HTML)


# ---------------------------------------------------------
# ADMIN / OFFICER PAPER MANAGEMENT
# ---------------------------------------------------------

ADMIN_HTML = """
<!DOCTYPE html>
<html>

<head>

<title>Question Paper Management</title>

<style>

body {
    font-family: Arial;
    margin: 40px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    border: 1px solid #ccc;
    padding: 10px;
}

th {
    background: #ddd;
}

input, button {
    padding: 8px;
}

</style>

</head>

<body>

<h1>Question Paper Management</h1>

<p>
Logged in as {{ username }} ({{ role }})
</p>

<a href="/dashboard">Dashboard</a>

<table>

<tr>
    <th>ID</th>
    <th>Title</th>
    <th>Status</th>
    <th>Hash</th>
    <th>Action</th>
</tr>

{% for paper in papers %}

<tr>

<td>{{ paper["id"] }}</td>

<td>{{ paper["title"] }}</td>

<td>{{ paper["status"] }}</td>

<td>
{{ paper["sha256_hash"][:20] }}...
</td>

<td>

{% if role in ["Officer", "Admin"] and paper["status"] == "Pending" %}

<a href="/approve/{{ paper['id'] }}">
Approve
</a>

{% endif %}

{% if role in ["Controller", "Admin"] and paper["status"] == "Approved" %}

<form method="POST"
      action="/schedule/{{ paper['id'] }}">

<input type="datetime-local"
       name="release_time"
       required>

<button type="submit">
Schedule Release
</button>

</form>

{% endif %}

</td>

</tr>

{% endfor %}

</table>

</body>

</html>
"""


@app.route("/admin/papers")
@login_required
@role_required("Officer", "Controller", "Admin")
def admin_papers():

    conn = get_db()

    papers = conn.execute("""
        SELECT * FROM papers
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template_string(
        ADMIN_HTML,
        username=session["username"],
        role=session["role"],
        papers=papers
    )


# ---------------------------------------------------------
# APPROVE QUESTION PAPER
# ---------------------------------------------------------

@app.route("/approve/<int:paper_id>")
@login_required
@role_required("Officer", "Admin")
def approve(paper_id):

    conn = get_db()

    conn.execute("""
        UPDATE papers
        SET status = 'Approved'
        WHERE id = ?
    """, (paper_id,))

    conn.commit()
    conn.close()

    log_action("Question Paper Approved", paper_id)

    return redirect(url_for("admin_papers"))


# ---------------------------------------------------------
# SCHEDULE RELEASE
# ---------------------------------------------------------

@app.route("/schedule/<int:paper_id>", methods=["POST"])
@login_required
@role_required("Controller", "Admin")
def schedule(paper_id):

    release_time = request.form["release_time"]

    conn = get_db()

    conn.execute("""
        UPDATE papers
        SET release_time = ?,
            status = 'Scheduled'
        WHERE id = ?
    """, (
        release_time,
        paper_id
    ))

    conn.commit()
    conn.close()

    log_action("Question Paper Release Scheduled", paper_id)

    return redirect(url_for("admin_papers"))


# ---------------------------------------------------------
# VIEW QUESTION PAPER
# ---------------------------------------------------------

@app.route("/view/<int:paper_id>")
@login_required
def view_paper(paper_id):

    conn = get_db()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    conn.close()

    if not paper:
        return "Question paper not found.", 404

    # Check release time
    if not paper["release_time"]:
        return "Question paper has not been released yet.", 403

    release_time = datetime.fromisoformat(
        paper["release_time"]
    )

    if datetime.now() < release_time:

        log_action(
            "Unauthorized Pre-Release Access Attempt",
            paper_id
        )

        return "Access Denied: Question paper has not been released.", 403

    # Automatically mark as released
    if paper["status"] != "Released":

        conn = get_db()

        conn.execute("""
            UPDATE papers
            SET status = 'Released'
            WHERE id = ?
        """, (paper_id,))

        conn.commit()
        conn.close()

    filepath = os.path.join(
        UPLOAD_FOLDER,
        paper["stored_filename"]
    )

    if not os.path.exists(filepath):
        return "File not found.", 404

    log_action(
        "Question Paper Viewed",
        paper_id
    )

    return send_file(filepath)


# ---------------------------------------------------------
# DOWNLOAD QUESTION PAPER
# ---------------------------------------------------------

@app.route("/download/<int:paper_id>")
@login_required
def download(paper_id):

    conn = get_db()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    conn.close()

    if not paper:
        return "Question paper not found.", 404

    if not paper["release_time"]:
        return "Question paper has not been released.", 403

    release_time = datetime.fromisoformat(
        paper["release_time"]
    )

    if datetime.now() < release_time:

        log_action(
            "Unauthorized Download Attempt",
            paper_id
        )

        return "Download denied: Question paper has not been released.", 403

    filepath = os.path.join(
        UPLOAD_FOLDER,
        paper["stored_filename"]
    )

    if not os.path.exists(filepath):
        return "File not found.", 404

    log_action(
        "Question Paper Downloaded",
        paper_id
    )

    return send_file(
        filepath,
        as_attachment=True,
        download_name=paper["filename"]
    )


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():

    log_action("Logout")

    session.clear()

    return redirect(url_for("login"))


# ---------------------------------------------------------
# START APPLICATION
# ---------------------------------------------------------

if _name_ == "_main_":

    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
