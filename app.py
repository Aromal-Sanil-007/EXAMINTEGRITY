from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib
import hmac
import os
import uuid

from datetime import datetime
from werkzeug.utils import secure_filename


app = Flask(__name__)

# Folder for uploaded files
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 16 MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Create uploads folder if it does not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():

    conn = sqlite3.connect("examintegrity.db")

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# AUDIT LOGGING
# ============================================================

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


# ============================================================
# ERROR PAGE
# ============================================================

def show_error(title, message, back_url="/", back_text="Go Back"):

    return render_template(
        "error.html",
        title=title,
        message=message,
        back_url=back_url,
        back_text=back_text
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# PDF VALIDATION
# ============================================================

def is_valid_pdf(file_data):

    if not file_data:
        return False

    return file_data.startswith(b"%PDF-")


# ============================================================
# FILE TOO LARGE ERROR
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    add_audit_log(
        "SECURITY EVENT",
        "File upload was rejected because it exceeded the 16 MB limit."
    )

    return show_error(
        "File Too Large",
        "The selected file exceeds the maximum allowed size of 16 MB.",
        url_for("upload_page"),
        "Choose Smaller File"
    ), 413


# ============================================================
# HOME / DASHBOARD
# ============================================================

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

    total_verifications = conn.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
    """).fetchone()[0]

    exact_matches = conn.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
        AND details LIKE '%Result: EXACT MATCH%'
    """).fetchone()[0]

    different_files = conn.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action = 'PAPER VERIFIED'
        AND details LIKE '%Result: DIFFERENT FILE%'
    """).fetchone()[0]

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


# ============================================================
# UPLOAD PAGE
# ============================================================

@app.route("/upload")
def upload_page():

    return render_template("upload.html")


# ============================================================
# VERIFICATION PAGE
# ============================================================

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


# ============================================================
# VERIFY PAPER
# ============================================================

@app.route("/verify-paper", methods=["POST"])
def verify_paper():

    # Get selected paper ID
    paper_id = request.form.get("paper_id")

    if not paper_id:

        add_audit_log(
            "SECURITY EVENT",
            "Verification request rejected because no registered paper was selected."
        )

        return show_error(
            "Paper Not Selected",
            "Please select a registered examination paper before verifying.",
            url_for("verify_page"),
            "Choose Paper"
        )

    # Convert paper ID to integer
    try:

        paper_id = int(paper_id)

    except (ValueError, TypeError):

        add_audit_log(
            "SECURITY EVENT",
            "Verification request rejected because an invalid paper ID was supplied."
        )

        return show_error(
            "Invalid Paper ID",
            "The selected paper ID is invalid.",
            url_for("verify_page"),
            "Try Again"
        )

    # Get suspected file
    suspected_file = request.files.get("suspected_paper")

    if suspected_file is None:

        add_audit_log(
            "SECURITY EVENT",
            "Verification request rejected because no suspected paper was supplied."
        )

        return show_error(
            "No File Selected",
            "Please select a suspected examination paper before continuing.",
            url_for("verify_page"),
            "Choose File"
        )

    if suspected_file.filename == "":

        add_audit_log(
            "SECURITY EVENT",
            "Verification request rejected because the selected filename was empty."
        )

        return show_error(
            "No File Selected",
            "Please select a suspected examination paper before continuing.",
            url_for("verify_page"),
            "Choose File"
        )

    # Check file extension
    if not suspected_file.filename.lower().endswith(".pdf"):

        add_audit_log(
            "SECURITY EVENT",
            f"Verification rejected non-PDF file '{suspected_file.filename}'."
        )

        return show_error(
            "Invalid File Type",
            "Only PDF files are allowed. Please select a PDF document.",
            url_for("verify_page"),
            "Try Again"
        )

    # Read file
    suspected_data = suspected_file.read()

    # Check actual PDF signature
    if not is_valid_pdf(suspected_data):

        add_audit_log(
            "SECURITY EVENT",
            f"Verification rejected invalid PDF file '{suspected_file.filename}'."
        )

        return show_error(
            "Invalid PDF File",
            "The selected file does not appear to be a valid PDF document.",
            url_for("verify_page"),
            "Try Again"
        )

    # Generate SHA-256 fingerprint
    suspected_fingerprint = hashlib.sha256(
        suspected_data
    ).hexdigest()

    # Find registered paper
    conn = get_db_connection()

    original_paper = conn.execute(
        "SELECT * FROM papers WHERE id = ?",
        (paper_id,)
    ).fetchone()

    conn.close()

    if original_paper is None:

        add_audit_log(
            "SECURITY EVENT",
            f"Verification attempted using non-existent paper ID {paper_id}."
        )

        return show_error(
            "Paper Not Found",
            "The selected original examination paper could not be found in the database.",
            url_for("verify_page"),
            "Back to Verification"
        )

    # Get registered fingerprint
    original_fingerprint = original_paper["fingerprint"]

    # Secure fingerprint comparison
    if hmac.compare_digest(
        original_fingerprint,
        suspected_fingerprint
    ):

        result = "EXACT MATCH"

        result_message = (
            "The suspected paper has the same digital fingerprint "
            "as the registered paper."
        )

    else:

        result = "DIFFERENT FILE"

        result_message = (
            "The suspected paper has a different digital fingerprint. "
            "It may have been modified or recreated."
        )

    print("AUDIT LOG:", result)

    # Add verification event to audit trail
    add_audit_log(
        "PAPER VERIFIED",
        f"Compared '{original_paper['filename']}' "
        f"with '{suspected_file.filename}'. "
        f"Result: {result}"
    )

    return render_template(
        "verification_result.html",
        original_paper=original_paper,
        suspected_filename=suspected_file.filename,
        original_fingerprint=original_fingerprint,
        suspected_fingerprint=suspected_fingerprint,
        result=result,
        result_message=result_message
    )


# ============================================================
# UPLOAD ORIGINAL PAPER
# ============================================================

@app.route("/upload-paper", methods=["POST"])
def upload_paper():

    # Check whether file exists in request
    if "paper" not in request.files:

        add_audit_log(
            "SECURITY EVENT",
            "Upload request rejected because the paper field was missing."
        )

        return show_error(
            "No File Selected",
            "Please select an examination paper before uploading.",
            url_for("upload_page"),
            "Choose File"
        )

    file = request.files["paper"]

    # Check filename
    if file.filename == "":

        add_audit_log(
            "SECURITY EVENT",
            "Upload request rejected because no filename was supplied."
        )

        return show_error(
            "No File Selected",
            "You have not selected any file. Please choose a PDF document.",
            url_for("upload_page"),
            "Try Again"
        )

    # Check extension
    if not file.filename.lower().endswith(".pdf"):

        add_audit_log(
            "SECURITY EVENT",
            f"Upload rejected non-PDF file '{file.filename}'."
        )

        return show_error(
            "Invalid File Type",
            "Only PDF files are accepted by EXAMINTEGRITY.",
            url_for("upload_page"),
            "Try Again"
        )

    # Read file data
    file_data = file.read()

    # Validate actual PDF
    if not is_valid_pdf(file_data):

        add_audit_log(
            "SECURITY EVENT",
            f"Upload rejected invalid PDF file '{file.filename}'."
        )

        return show_error(
            "Invalid PDF File",
            "The selected file is not recognised as a valid PDF document.",
            url_for("upload_page"),
            "Try Again"
        )

    # Generate SHA-256 fingerprint
    fingerprint = hashlib.sha256(
        file_data
    ).hexdigest()

    # Clean filename
    original_filename = secure_filename(
        file.filename
    )

    if original_filename == "":

        add_audit_log(
            "SECURITY EVENT",
            "Upload rejected because the filename became empty after sanitization."
        )

        return show_error(
            "Invalid Filename",
            "The selected file has an invalid filename. Please rename it and try again.",
            url_for("upload_page"),
            "Try Again"
        )

    # Check for duplicate fingerprint
    conn = get_db_connection()

    existing_paper = conn.execute(
        "SELECT * FROM papers WHERE fingerprint = ?",
        (fingerprint,)
    ).fetchone()

    conn.close()

    if existing_paper is not None:

        add_audit_log(
            "DUPLICATE UPLOAD BLOCKED",
            f"Duplicate file '{original_filename}' "
            f"matched existing paper '{existing_paper['filename']}'."
        )

        return show_error(
            "Duplicate Paper Detected",
            f"This examination paper is already registered. "
            f"Existing filename: {existing_paper['filename']}",
            url_for("upload_page"),
            "Upload Another Paper"
        )

    # Generate unique physical filename
    unique_filename = (
        str(uuid.uuid4()) + "_" + original_filename
    )

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_filename
    )

    # Save file
    try:

        with open(file_path, "wb") as saved_file:

            saved_file.write(file_data)

    except OSError:

        add_audit_log(
            "SECURITY EVENT",
            f"Server failed to save uploaded file '{original_filename}'."
        )

        return show_error(
            "Upload Failed",
            "The server could not save the examination paper. Please try again.",
            url_for("upload_page"),
            "Try Again"
        )

    # Store paper in database
    try:

        conn = get_db_connection()

        conn.execute("""
            INSERT INTO papers
            (filename, fingerprint, uploaded_by, uploaded_at)
            VALUES (?, ?, ?, ?)
        """, (
            original_filename,
            fingerprint,
            "Admin",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

    except sqlite3.Error:

        # Remove file if database insertion fails
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
            "Try Again"
        )

    # Record successful upload
    add_audit_log(
        "PAPER UPLOADED",
        f"File '{original_filename}' was uploaded "
        f"and fingerprinted successfully."
    )

    # Return to dashboard
    return redirect(
        url_for("home")
    )


# ============================================================
# AUDIT TRAIL
# ============================================================

@app.route("/admin")
def admin_page():
    conn = get_db_connection()

    papers = conn.execute("""
        SELECT *
        FROM papers
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        papers=papers
    )

@app.route("/delete-paper/<int:paper_id>", methods=["POST"])
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
            "Back to Admin"
        )

    conn.execute(
        "DELETE FROM papers WHERE id = ?",
        (paper_id,)
    )

    conn.commit()
    conn.close()

    add_audit_log(
        "PAPER DELETED",
        f"Registered paper '{paper['filename']}' "
        f"with ID {paper_id} was deleted by Admin."
    )

    return redirect(url_for("admin_page"))


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


# ============================================================
# GENERAL SERVER ERROR
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    return show_error(
        "Server Error",
        "An unexpected error occurred while processing the request.",
        url_for("home"),
        "Back to Dashboard"
    ), 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_db()

    app.run(debug=True)