
from flask import (
    Flask, request, redirect, url_for, session,
    send_file, render_template, flash
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import sqlite3
import os
import hashlib

app = Flask(__name__)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "secure-question-paper-secret-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(BASE_DIR, "question_paper.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "secure_papers")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

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

    demo_users = [
        ("admin", "admin123", "Admin"),
        ("setter", "setter123", "Question Setter"),
        ("officer", "officer123", "Officer"),
        ("controller", "controller123", "Controller"),
        ("student", "student123", "Candidate")
    ]

    for username, password, role in demo_users:

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not existing:
            conn.execute(
                """
                INSERT INTO users
                (username, password, role)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    role
                )
            )

    conn.commit()
    conn.close()


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def log_action(action, paper_id=None):

    username = session.get("username", "Unknown")

    conn = get_db()

    conn.execute(
        """
        INSERT INTO audit_logs
        (username, action, paper_id, timestamp)
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            action,
            paper_id,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


# --------------------------------------------------
# LOGIN REQUIRED
# --------------------------------------------------

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# ROLE BASED ACCESS CONTROL
# --------------------------------------------------

def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "role" not in session:
                return redirect(url_for("login"))

            if session["role"] not in allowed_roles:

                log_action("Unauthorized Access Attempt")

                return """
                <h2>Access Denied</h2>
                <p>You are not authorized to access this page.</p>
                <a href="/dashboard">Back to Dashboard</a>
                """, 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_action("Successful Login")

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


# --------------------------------------------------
# CHECK RELEASE TIME
# --------------------------------------------------

def is_released(paper):

    if not paper["release_time"]:
        return False

    try:
        release_time = datetime.fromisoformat(
            paper["release_time"]
        )

        # Compare using PythonAnywhere server time
        now = datetime.now()

        return now >= release_time

    except (ValueError, TypeError):
        return False


# --------------------------------------------------
# AUTOMATIC STATUS UPDATE
# --------------------------------------------------

def update_released_papers():

    conn = get_db()

    papers = conn.execute(
        """
        SELECT id, status, release_time
        FROM papers
        WHERE status = 'Scheduled'
        """
    ).fetchall()

    released_ids = []

    for paper in papers:

        if is_released(paper):

            conn.execute(
                """
                UPDATE papers
                SET status = 'Released'
                WHERE id = ?
                  AND status = 'Scheduled'
                """,
                (paper["id"],)
            )

            if conn.total_changes:
                released_ids.append(paper["id"])

    conn.commit()
    conn.close()

    for paper_id in released_ids:
        log_action(
            "Question Paper Released",
            paper_id
        )


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    update_released_papers()

    conn = get_db()

    papers = conn.execute(
        """
        SELECT *
        FROM papers
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        papers=papers
    )


# --------------------------------------------------
# UPLOAD QUESTION PAPER
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
@role_required("Question Setter", "Admin")
def upload():

    if request.method == "POST":

        title = request.form.get(
            "title", ""
        ).strip()

        file = request.files.get("paper")

        if not title:
            flash("Please enter the question paper title.")
            return redirect(url_for("upload"))

        if not file or file.filename == "":
            flash("Please select a question paper.")
            return redirect(url_for("upload"))

        if not file.filename.lower().endswith(".pdf"):
            flash("Only PDF files are allowed.")
            return redirect(url_for("upload"))

        original_name = secure_filename(file.filename)

        if not original_name:
            flash("Invalid filename.")
            return redirect(url_for("upload"))

        timestamp = datetime.now().strftime(
            "%Y%m%d%H%M%S%f"
        )

        stored_name = timestamp + "_" + original_name

        filepath = os.path.join(
            UPLOAD_FOLDER,
            stored_name
        )

        file.save(filepath)

        sha256 = hashlib.sha256()

        with open(filepath, "rb") as uploaded_file:
            for block in iter(
                lambda: uploaded_file.read(4096),
                b""
            ):
                sha256.update(block)

        file_hash = sha256.hexdigest()

        conn = get_db()

        cursor = conn.execute(
            """
            INSERT INTO papers (
                title,
                filename,
                stored_filename,
                uploaded_by,
                upload_time,
                sha256_hash,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                original_name,
                stored_name,
                session["user_id"],
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                file_hash,
                "Pending"
            )
        )

        paper_id = cursor.lastrowid

        conn.commit()
        conn.close()

        log_action(
            "Question Paper Uploaded",
            paper_id
        )

        flash("Question paper uploaded successfully.")

        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# --------------------------------------------------
# ADMIN / OFFICER PAPER MANAGEMENT
# --------------------------------------------------

@app.route("/admin/papers")
@login_required
@role_required(
    "Officer",
    "Controller",
    "Admin"
)
def admin_papers():

    update_released_papers()

    conn = get_db()

    papers = conn.execute(
        """
        SELECT *
        FROM papers
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin_papers.html",
        username=session["username"],
        role=session["role"],
        papers=papers
    )


# --------------------------------------------------
# APPROVE QUESTION PAPER
# --------------------------------------------------

@app.route("/approve/<int:paper_id>")
@login_required
@role_required("Officer", "Admin")
def approve(paper_id):

    conn = get_db()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    if not paper:
        conn.close()
        return "Question paper not found.", 404

    if paper["status"] != "Pending":
        conn.close()
        return "Only pending papers can be approved.", 400

    conn.execute(
        """
        UPDATE papers
        SET status = 'Approved'
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()
    conn.close()

    log_action(
        "Question Paper Approved",
        paper_id
    )

    flash("Question paper approved.")

    return redirect(url_for("admin_papers"))


# --------------------------------------------------
# SCHEDULE RELEASE
# --------------------------------------------------

@app.route(
    "/schedule/<int:paper_id>",
    methods=["POST"]
)
@login_required
@role_required("Controller", "Admin")
def schedule(paper_id):

    release_time = request.form.get(
        "release_time", ""
    ).strip()

    if not release_time:
        return "Release time is required.", 400

    try:
        parsed_time = datetime.fromisoformat(release_time)
    except (ValueError, TypeError):
        return "Invalid release time format.", 400

    # Store a consistent local datetime string
    release_time = parsed_time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    if not paper:
        conn.close()
        return "Question paper not found.", 404

    if paper["status"] != "Approved":
        conn.close()
        return "Only approved papers can be scheduled.", 400

    conn.execute(
        """
        UPDATE papers
        SET release_time = ?,
            status = 'Scheduled'
        WHERE id = ?
        """,
        (
            release_time,
            paper_id
        )
    )

    conn.commit()
    conn.close()

    log_action(
        "Question Paper Release Scheduled",
        paper_id
    )

    flash("Question paper release scheduled.")

    return redirect(url_for("admin_papers"))


# --------------------------------------------------
# VIEW QUESTION PAPER
# --------------------------------------------------

@app.route("/view/<int:paper_id>")
@login_required
def view_paper(paper_id):

    # Update any papers whose scheduled time has passed
    update_released_papers()

    conn = get_db()

    paper = conn.execute(
        """
        SELECT *
        FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    ).fetchone()

    conn.close()

    if not paper:
        return "Question paper not found.", 404

    if not is_released(paper):
        log_action(
            "Pre-Release Access Attempt",
            paper_id
        )

        return """
        <h2>Access Denied</h2>
        <p>The question paper has not been released yet.</p>
        <a href="/dashboard">Back to Dashboard</a>
        """, 403

    filepath = os.path.join(
        UPLOAD_FOLDER,
        paper["stored_filename"]
    )

    if not os.path.exists(filepath):
        return "Question paper file not found.", 404

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        for block in iter(
            lambda: file.read(4096),
            b""
        ):
            sha256.update(block)

    current_hash = sha256.hexdigest()

    if current_hash != paper["sha256_hash"]:

        log_action(
            "Integrity Verification Failed",
            paper_id
        )

        return """
        <h2>Security Alert</h2>
        <p>Question paper integrity verification failed.</p>
        """, 500

    conn = get_db()

    conn.execute(
        """
        UPDATE papers
        SET status = 'Released'
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()
    conn.close()

    log_action(
        "Question Paper Viewed",
        paper_id
    )

    return send_file(
        filepath,
        as_attachment=False,
        download_name=paper["filename"]
    )


# --------------------------------------------------
# DOWNLOAD QUESTION PAPER
# --------------------------------------------------

@app.route("/download/<int:paper_id>")
@login_required
def download(paper_id):

    # Update scheduled papers before checking access
    update_released_papers()

    conn = get_db()

    paper = conn.execute(
        """
        SELECT *
        FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    ).fetchone()

    conn.close()

    if not paper:
        return "Question paper not found.", 404

    if not is_released(paper):

        log_action(
            "Pre-Release Download Attempt",
            paper_id
        )

        return """
        <h2>Download Denied</h2>
        <p>The question paper has not been released.</p>
        <a href="/dashboard">Back to Dashboard</a>
        """, 403

    filepath = os.path.join(
        UPLOAD_FOLDER,
        paper["stored_filename"]
    )

    if not os.path.exists(filepath):
        return "Question paper file not found.", 404

    # Integrity verification
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        for block in iter(
            lambda: file.read(4096),
            b""
        ):
            sha256.update(block)

    current_hash = sha256.hexdigest()

    if current_hash != paper["sha256_hash"]:

        log_action(
            "Integrity Verification Failed",
            paper_id
        )

        return """
        <h2>Security Alert</h2>
        <p>Question paper integrity verification failed.</p>
        """, 500

    conn = get_db()

    conn.execute(
        """
        UPDATE papers
        SET status = 'Released'
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()
    conn.close()

    log_action(
        "Question Paper Downloaded",
        paper_id
    )

    return send_file(
        filepath,
        as_attachment=True,
        download_name=paper["filename"]
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    log_action("User Logged Out")

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
