from flask import Flask, render_template, request, redirect, url_for, session
from pypdf import PdfReader
from difflib import SequenceMatcher
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

import sqlite3
import hashlib
import hmac
import os
import uuid
from datetime import datetime


app = Flask(__name__)

# --------------------------------------------------
# FLASK SESSION SECURITY
# --------------------------------------------------

app.secret_key = os.environ.get(
    "EXAMINTEGRITY_SECRET_KEY",
    "change-this-secret-key-before-deployment"
)


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DATABASE_FILE = os.path.join(BASE_DIR, "examintegrity.db")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------
# AUDIT LOG
# --------------------------------------------------

def add_audit_log(action, details):

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO audit_logs
        (action, details, created_at)
        VALUES (?, ?, ?)
    """, (
        action,
        details,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# ERROR PAGE
# --------------------------------------------------

def show_error(
    title,
    message,
    back_url="/",
    back_text="Go Back",
    status_code=None
):

    response = render_template(
        "error.html",
        title=title,
        message=message,
        back_url=back_url,
        back_text=back_text
    )

    if status_code is not None:
        return response, status_code

    return response


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_db():

    conn = get_db_connection()

    # Examination papers table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            stored_filename TEXT
        )
    """)

    # Audit logs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Admin accounts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Check old papers table structure
    paper_columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(papers)"
        ).fetchall()
    ]

    # Add stored_filename if old database does not have it
    if "stored_filename" not in paper_columns:

        conn.execute(
            "ALTER TABLE papers ADD COLUMN stored_filename TEXT"
        )

    conn.commit()
    conn.close()


# --------------------------------------------------
# ADMIN LOGIN PROTECTION
# --------------------------------------------------

def admin_required(route_function):

    @wraps(route_function)
    def wrapper(*args, **kwargs):

        if not session.get("admin_logged_in"):

            return redirect(url_for("admin_login"))

        return route_function(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# PDF VALIDATION
# --------------------------------------------------

def is_valid_pdf(file_data):

    if not file_data:
        return False

    return file_data.startswith(b"%PDF-")


# --------------------------------------------------
# PDF TEXT EXTRACTION
# --------------------------------------------------

def extract_pdf_text(file_path):

    try:

        reader = PdfReader(file_path)

        extracted_text = ""

        for page in reader.pages:

            page_text = page.extract_text()

            if page_text:

                extracted_text += page_text + "\n"

        return extracted_text

    except Exception as error:

        print("PDF TEXT EXTRACTION ERROR:", error)

        return ""


# --------------------------------------------------
# TEXT NORMALIZATION
# --------------------------------------------------

def normalize_text(text):

    text = text.lower()

    text = " ".join(text.split())

    return text


# --------------------------------------------------
# TEXT SIMILARITY
# --------------------------------------------------

def calculate_text_similarity(original_text, uploaded_text):

    original_text = normalize_text(original_text)
    uploaded_text = normalize_text(uploaded_text)

    if not original_text or not uploaded_text:

        return 0

    similarity = SequenceMatcher(
        None,
        original_text,
        uploaded_text
    ).ratio()

    return round(similarity * 100, 2)


# --------------------------------------------------
# FIND STORED PAPER
# --------------------------------------------------

def find_stored_file(paper):

    stored_filename = paper["stored_filename"]

    if stored_filename:

        stored_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            stored_filename
        )

        if os.path.isfile(stored_path):

            return stored_path

    original_filename = paper["filename"]

    direct_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        original_filename
    )

    if os.path.isfile(direct_path):

        return direct_path

    try:

        possible_files = os.listdir(
            app.config["UPLOAD_FOLDER"]
        )

        matching_files = [
            item
            for item in possible_files
            if item.endswith("_" + original_filename)
        ]

        if matching_files:

            matching_files.sort()

            return os.path.join(
                app.config["UPLOAD_FOLDER"],
                matching_files[0]
            )

    except OSError:

        return None

    return None


# ==================================================
# ADMIN LOGIN
# ==================================================

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    # Check whether an admin account already exists
    conn = get_db_connection()

    admin = conn.execute(
        "SELECT * FROM admins LIMIT 1"
    ).fetchone()

    conn.close()

    # If no admin exists, send user to setup
    if admin is None:

        return redirect(url_for("admin_setup"))

    # Handle login form
    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db_connection()

        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        # Check username and password
        if admin and check_password_hash(
            admin["password_hash"],
            password
        ):

            session["admin_logged_in"] = True

            session["admin_username"] = admin["username"]

            add_audit_log(
                "ADMIN LOGIN",
                f"Administrator '{admin['username']}' logged in successfully."
            )

            return redirect(url_for("admin_page"))

        # Wrong credentials
        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


# ==================================================
# FIRST ADMIN ACCOUNT SETUP
# ==================================================

@app.route("/admin-setup", methods=["GET", "POST"])
def admin_setup():

    conn = get_db_connection()

    admin_count = conn.execute(
        "SELECT COUNT(*) FROM admins"
    ).fetchone()[0]

    conn.close()

    # Do not allow another setup if admin already exists
    if admin_count > 0:

        return redirect(url_for("admin_login"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # Username validation
        if not username:

            return render_template(
                "admin_setup.html",
                error="Username is required."
            )

        # Password validation
        if not password:

            return render_template(
                "admin_setup.html",
                error="Password is required."
            )

        # Minimum password length
        if len(password) < 8:

            return render_template(
                "admin_setup.html",
                error="Password must contain at least 8 characters."
            )

        # Confirm password
        if password != confirm_password:

            return render_template(
                "admin_setup.html",
                error="Passwords do not match."
            )

        # Hash password
        password_hash = generate_password_hash(password)

        try:

            conn = get_db_connection()

            conn.execute("""
                INSERT INTO admins
                (username, password_hash, created_at)
                VALUES (?, ?, ?)
            """, (
                username,
                password_hash,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:

            return render_template(
                "admin_setup.html",
                error="This username already exists."
            )

        add_audit_log(
            "ADMIN CREATED",
            f"Administrator account '{username}' was created."
        )

        return redirect(url_for("admin_login"))

    return render_template("admin_setup.html")


# ==================================================
# ADMIN LOGOUT
# ==================================================

@app.route("/admin-logout")
@admin_required
def admin_logout():

    username = session.get(
        "admin_username",
        "Administrator"
    )

    session.clear()

    add_audit_log(
        "ADMIN LOGOUT",
        f"Administrator '{username}' logged out."
    )

    return redirect(url_for("home"))


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/")
def home():

    conn = get_db_connection()

    papers = conn.execute(
        "SELECT * FROM papers ORDER BY id DESC"
    ).fetchall()

    audit_logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10"
    ).fetchall()

    total_papers = conn.execute(
        "SELECT COUNT(*) FROM papers"
    ).fetchone()[0]

    total_verifications = conn.execute(
        """
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
        """
    ).fetchone()[0]

    exact_matches = conn.execute(
        """
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
        AND details LIKE '%Result: EXACT MATCH%'
        """
    ).fetchone()[0]

    different_files = conn.execute(
        """
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
        AND (
            details LIKE '%Result: DIFFERENT FILE%'
            OR details LIKE '%Result: DIFFERENT PAPER%'
        )
        """
    ).fetchone()[0]

    conn.close()

    return render_template(
        "index.html",
        papers=papers,
        audit_logs=audit_logs,
        total_papers=total_papers,
        total_verifications=total_verifications,
        exact_matches=exact_matches,
        different_files=different_files
    )


# ==================================================
# UPLOAD PAGE
# ==================================================

@app.route("/upload")
def upload_page():

    return render_template("upload.html")


# ==================================================
# VERIFICATION PAGE
# ==================================================

@app.route("/verify")
def verify_page():

    conn = get_db_connection()

    papers = conn.execute(
        "SELECT * FROM papers ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "verify.html",
        papers=papers
    )


# ==================================================
# VERIFY PAPER
# ==================================================

@app.route("/verify-paper", methods=["POST"])
def verify_paper():

    paper_id = request.form.get("paper_id")

    uploaded_file = (
        request.files.get("suspected_paper")
        or request.files.get("verification_file")
        or request.files.get("file")
    )

    if not paper_id:

        return show_error(
            "Missing Paper",
            "Please select a registered paper.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    if uploaded_file is None:

        return show_error(
            "No File Selected",
            "Please upload a PDF file to verify.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    if uploaded_file.filename == "":

        return show_error(
            "No File Selected",
            "Please select a PDF file before continuing.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    try:

        paper_id = int(paper_id)

    except (TypeError, ValueError):

        return show_error(
            "Invalid Paper",
            "The selected paper ID is invalid.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    if not uploaded_file.filename.lower().endswith(".pdf"):

        add_audit_log(
            "SECURITY EVENT",
            f"Verification rejected non-PDF file '{uploaded_file.filename}'."
        )

        return show_error(
            "Invalid File Type",
            "Only PDF files are allowed.",
            url_for("verify_page"),
            "Try Again",
            400
        )

    uploaded_bytes = uploaded_file.read()

    if not is_valid_pdf(uploaded_bytes):

        add_audit_log(
            "SECURITY EVENT",
            f"Verification rejected invalid PDF file '{uploaded_file.filename}'."
        )

        return show_error(
            "Invalid PDF File",
            "The uploaded file is not recognised as a valid PDF document.",
            url_for("verify_page"),
            "Try Again",
            400
        )

    uploaded_hash = hashlib.sha256(
        uploaded_bytes
    ).hexdigest()

    conn = get_db_connection()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    conn.close()

    if paper is None:

        return show_error(
            "Paper Not Found",
            "The selected registered paper was not found.",
            url_for("verify_page"),
            "Back to Verification",
            404
        )

    original_hash = paper["fingerprint"]

    similarity = 0

    # --------------------------------------------------
    # EXACT HASH MATCH
    # --------------------------------------------------

    if hmac.compare_digest(
        uploaded_hash,
        original_hash
    ):

        result = "EXACT MATCH"

        similarity = 100

        result_message = (
            "The suspected paper has exactly the same SHA-256 "
            "fingerprint as the registered paper. This is treated "
            "as a high-risk exact match."
        )

    # --------------------------------------------------
    # TEXT COMPARISON
    # --------------------------------------------------

    else:

        temporary_filename = (
            f"verify_{uuid.uuid4().hex}.pdf"
        )

        temporary_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            temporary_filename
        )

        try:

            with open(
                temporary_path,
                "wb"
            ) as temporary_file:

                temporary_file.write(
                    uploaded_bytes
                )

            original_file_path = find_stored_file(
                paper
            )

            if original_file_path is None:

                result = "DIFFERENT FILE"

                result_message = (
                    "The fingerprints are different, but the "
                    "original registered PDF could not be located "
                    "for text comparison."
                )

            else:

                original_text = extract_pdf_text(
                    original_file_path
                )

                uploaded_text = extract_pdf_text(
                    temporary_path
                )

                similarity = calculate_text_similarity(
                    original_text,
                    uploaded_text
                )

                if similarity >= 70:

                    result = "MODIFIED COPY DETECTED"

                    result_message = (
                        "The SHA-256 fingerprints are different, "
                        f"but the extracted text is {similarity}% "
                        "similar. This may be a modified copy of "
                        "the registered paper."
                    )

                elif similarity >= 50:

                    result = "POSSIBLE SIMILARITY"

                    result_message = (
                        "The uploaded paper has a different "
                        f"fingerprint and {similarity}% text "
                        "similarity with the registered paper. "
                        "Manual checking is recommended."
                    )

                else:

                    result = "DIFFERENT FILE"

                    result_message = (
                        "The uploaded paper has a different "
                        f"fingerprint and only {similarity}% "
                        "text similarity with the registered paper."
                    )

        except Exception as error:

            print(
                "VERIFICATION ERROR:",
                error
            )

            result = "DIFFERENT FILE"

            result_message = (
                "The files have different fingerprints. "
                "Text comparison could not be completed."
            )

        finally:

            if os.path.exists(
                temporary_path
            ):

                try:

                    os.remove(
                        temporary_path
                    )

                except OSError:

                    pass

    # --------------------------------------------------
    # AUDIT LOG
    # --------------------------------------------------

    audit_details = (
        f"Original paper: '{paper['filename']}'. "
        f"Uploaded file: "
        f"'{secure_filename(uploaded_file.filename)}'. "
        f"Result: {result}. "
        f"Similarity: {similarity}%."
    )

    add_audit_log(
        "PAPER VERIFIED",
        audit_details
    )

    return render_template(
        "verification_result.html",
        original_paper=paper,
        suspected_filename=uploaded_file.filename,
        original_fingerprint=original_hash,
        suspected_fingerprint=uploaded_hash,
        result=result,
        result_message=result_message,
        similarity=similarity
    )


# ==================================================
# UPLOAD PAPER
# ==================================================

@app.route("/upload-paper", methods=["POST"])
def upload_paper():

    if "paper" not in request.files:

        add_audit_log(
            "SECURITY EVENT",
            "Upload request rejected because the paper field was missing."
        )

        return show_error(
            "No File Selected",
            "Please select an examination paper before uploading.",
            url_for("upload_page"),
            "Choose File",
            400
        )

    uploaded_file = request.files["paper"]

    if uploaded_file.filename == "":

        add_audit_log(
            "SECURITY EVENT",
            "Upload request rejected because no filename was supplied."
        )

        return show_error(
            "No File Selected",
            "You have not selected any file. Please choose a PDF document.",
            url_for("upload_page"),
            "Try Again",
            400
        )

    if not uploaded_file.filename.lower().endswith(".pdf"):

        add_audit_log(
            "SECURITY EVENT",
            f"Upload rejected non-PDF file '{uploaded_file.filename}'."
        )

        return show_error(
            "Invalid File Type",
            "Only PDF files are accepted by EXAMINTEGRITY.",
            url_for("upload_page"),
            "Try Again",
            400
        )

    file_data = uploaded_file.read()

    if not is_valid_pdf(file_data):

        add_audit_log(
            "SECURITY EVENT",
            f"Upload rejected invalid PDF file '{uploaded_file.filename}'."
        )

        return show_error(
            "Invalid PDF File",
            "The selected file is not recognised as a valid PDF document.",
            url_for("upload_page"),
            "Try Again",
            400
        )

    fingerprint = hashlib.sha256(
        file_data
    ).hexdigest()

    original_filename = secure_filename(
        uploaded_file.filename
    )

    if original_filename == "":

        add_audit_log(
            "SECURITY EVENT",
            "Upload rejected because the filename became empty after sanitization."
        )

        return show_error(
            "Invalid Filename",
            "The selected file has an invalid filename. "
            "Please rename it and try again.",
            url_for("upload_page"),
            "Try Again",
            400
        )

    # --------------------------------------------------
    # DUPLICATE CHECK
    # --------------------------------------------------

    conn = get_db_connection()

    existing_paper = conn.execute(
        """
        SELECT *
        FROM papers
        WHERE fingerprint = ?
        """,
        (fingerprint,)
    ).fetchone()

    conn.close()

    if existing_paper is not None:

        add_audit_log(
            "DUPLICATE UPLOAD BLOCKED",
            f"Duplicate file '{original_filename}' matched "
            f"existing paper '{existing_paper['filename']}'."
        )

        return show_error(
            "Duplicate Paper Detected",
            f"This examination paper is already registered. "
            f"Existing filename: {existing_paper['filename']}",
            url_for("upload_page"),
            "Upload Another Paper",
            400
        )

    # --------------------------------------------------
    # UNIQUE STORAGE NAME
    # --------------------------------------------------

    unique_filename = (
        f"{uuid.uuid4().hex}_{original_filename}"
    )

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_filename
    )

    try:

        with open(
            file_path,
            "wb"
        ) as saved_file:

            saved_file.write(
                file_data
            )

    except OSError as error:

        print(
            "FILE SAVE ERROR:",
            error
        )

        add_audit_log(
            "SECURITY EVENT",
            f"Server failed to save uploaded file '{original_filename}'."
        )

        return show_error(
            "Upload Failed",
            "The server could not save the examination paper. "
            "Please try again.",
            url_for("upload_page"),
            "Try Again",
            500
        )

    # --------------------------------------------------
    # DATABASE INSERT
    # --------------------------------------------------

    try:

        conn = get_db_connection()

        conn.execute("""
            INSERT INTO papers
            (
                filename,
                fingerprint,
                uploaded_by,
                uploaded_at,
                stored_filename
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            original_filename,
            fingerprint,
            session.get(
                "admin_username",
                "Admin"
            ),
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            unique_filename
        ))

        conn.commit()
        conn.close()

    except sqlite3.Error as error:

        print(
            "DATABASE INSERT ERROR:",
            error
        )

        if os.path.exists(file_path):

            os.remove(file_path)

        add_audit_log(
            "SECURITY EVENT",
            f"Database error occurred while registering '{original_filename}'."
        )

        return show_error(
            "Registration Failed",
            "The paper could not be registered in the database.",
            url_for("upload_page"),
            "Try Again",
            500
        )

    add_audit_log(
        "PAPER UPLOADED",
        f"File '{original_filename}' was uploaded and fingerprinted successfully."
    )

    return redirect(
        url_for("home")
    )


# ==================================================
# ADMIN CONTROL CENTER
# ==================================================

@app.route("/admin")
@admin_required
def admin_page():

    conn = get_db_connection()

    papers = conn.execute(
        "SELECT * FROM papers ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        papers=papers
    )


# ==================================================
# DELETE PAPER
# ==================================================

@app.route(
    "/delete-paper/<int:paper_id>",
    methods=["POST"]
)
@admin_required
def delete_paper(paper_id):

    conn = get_db_connection()

    paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    if paper is None:

        conn.close()

        add_audit_log(
            "SECURITY EVENT",
            f"Deletion attempted for non-existent paper ID {paper_id}."
        )

        return show_error(
            "Paper Not Found",
            "The selected examination paper does not exist.",
            url_for("admin_page"),
            "Back to Admin",
            404
        )

    stored_path = find_stored_file(
        paper
    )

    conn.execute(
        "DELETE FROM papers WHERE id = ?",
        (paper_id,)
    )

    conn.commit()
    conn.close()

    # Delete physical PDF
    if stored_path and os.path.exists(
        stored_path
    ):

        try:

            os.remove(
                stored_path
            )

        except OSError as error:

            print(
                "FILE DELETE ERROR:",
                error
            )

    add_audit_log(
        "PAPER DELETED",
        f"Registered paper '{paper['filename']}' "
        f"with ID {paper_id} was deleted by "
        f"{session.get('admin_username', 'Admin')}."
    )

    return redirect(
        url_for("admin_page")
    )


# ==================================================
# AUDIT TRAIL
# ==================================================

@app.route("/audit-trail")
def audit_trail():

    conn = get_db_connection()

    audit_logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "audit_trail.html",
        audit_logs=audit_logs
    )


# ==================================================
# FILE TOO LARGE
# ==================================================

@app.errorhandler(413)
def file_too_large(error):

    add_audit_log(
        "SECURITY EVENT",
        "File upload rejected because it exceeded the 16 MB limit."
    )

    return show_error(
        "File Too Large",
        "The selected file exceeds the maximum allowed size of 16 MB.",
        url_for("upload_page"),
        "Choose Smaller File",
        413
    )


# ==================================================
# INTERNAL SERVER ERROR
# ==================================================

@app.errorhandler(500)
def internal_server_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        error
    )

    return show_error(
        "Server Error",
        "An unexpected error occurred while processing the request.",
        url_for("home"),
        "Back to Dashboard",
        500
    )


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )