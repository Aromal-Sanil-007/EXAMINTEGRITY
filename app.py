from flask import Flask, render_template, request, redirect, url_for
from pypdf import PdfReader
from difflib import SequenceMatcher
from werkzeug.utils import secure_filename

import sqlite3
import hashlib
import hmac
import os
import uuid
from datetime import datetime


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "examintegrity.db"
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 16 MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# AUDIT LOGGING
# ============================================================

def add_audit_log(action, details):
    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO audit_logs
        (
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            action,
            details,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# ERROR PAGE
# ============================================================

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


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    conn = get_db_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            stored_filename TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    # Add stored_filename to older databases if missing
    paper_columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(papers)"
        ).fetchall()
    ]

    if "stored_filename" not in paper_columns:
        conn.execute(
            "ALTER TABLE papers ADD COLUMN stored_filename TEXT"
        )

    conn.commit()
    conn.close()


# ============================================================
# PDF VALIDATION
# ============================================================

def is_valid_pdf(file_data):
    """
    Checks whether the uploaded file begins
    with the standard PDF file signature.
    """
    if not file_data:
        return False

    return file_data.startswith(b"%PDF-")


# ============================================================
# PDF TEXT EXTRACTION
# ============================================================

def extract_pdf_text(file_path):
    """
    Extracts readable text from every page of a PDF.

    Note:
    Scanned image-only PDFs may return empty text.
    """
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


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):
    """
    Converts text to lowercase and removes
    unnecessary spaces.
    """
    text = text.lower()
    text = " ".join(text.split())

    return text


# ============================================================
# TEXT SIMILARITY CALCULATION
# ============================================================

def calculate_text_similarity(original_text, uploaded_text):
    """
    Calculates the similarity between two PDF texts.

    Returns a percentage between 0 and 100.
    """
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


# ============================================================
# FILE PATH HELPER
# ============================================================

def find_stored_file(paper):
    """
    Finds the physical PDF connected to a database record.

    New records use stored_filename.

    Older records may use:
    1. The original filename
    2. A UUID_originalfilename pattern
    """

    stored_filename = paper["stored_filename"]

    # Check the stored filename used by new records
    if stored_filename:
        stored_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            stored_filename
        )

        if os.path.isfile(stored_path):
            return stored_path

    original_filename = paper["filename"]

    # Check the original filename
    direct_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        original_filename
    )

    if os.path.isfile(direct_path):
        return direct_path

    # Check older UUID_filename files
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


# ============================================================
# FILE TOO LARGE ERROR
# ============================================================

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


# ============================================================
# HOME / DASHBOARD
# ============================================================

@app.route("/")
def home():
    conn = get_db_connection()

    papers = conn.execute(
        """
        SELECT *
        FROM papers
        ORDER BY id DESC
        """
    ).fetchall()

    audit_logs = conn.execute(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 10
        """
    ).fetchall()

    total_papers = conn.execute(
        """
        SELECT COUNT(*)
        FROM papers
        """
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
        """
        SELECT *
        FROM papers
        ORDER BY id DESC
        """
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

    paper_id = request.form.get("paper_id")

    # Supports the current and older input names
    uploaded_file = (
        request.files.get("suspected_paper")
        or request.files.get("verification_file")
        or request.files.get("file")
    )

    # Check paper selection
    if not paper_id:
        return show_error(
            "Missing Paper",
            "Please select a registered paper.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    # Check uploaded file
    if uploaded_file is None:
        return show_error(
            "No File Selected",
            "Please upload a PDF file to verify.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    # Check filename
    if uploaded_file.filename == "":
        return show_error(
            "No File Selected",
            "Please select a PDF file before continuing.",
            url_for("verify_page"),
            "Back to Verification",
            400
        )

    # Validate paper ID
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

    # Validate file extension
    if not uploaded_file.filename.lower().endswith(".pdf"):
        add_audit_log(
            "SECURITY EVENT",
            (
                "Verification rejected non-PDF file "
                f"'{uploaded_file.filename}'."
            )
        )

        return show_error(
            "Invalid File Type",
            "Only PDF files are allowed.",
            url_for("verify_page"),
            "Try Again",
            400
        )

    # Read uploaded file
    uploaded_bytes = uploaded_file.read()

    # Validate PDF signature
    if not is_valid_pdf(uploaded_bytes):
        add_audit_log(
            "SECURITY EVENT",
            (
                "Verification rejected invalid PDF file "
                f"'{uploaded_file.filename}'."
            )
        )

        return show_error(
            "Invalid PDF File",
            "The uploaded file is not recognised as a valid PDF document.",
            url_for("verify_page"),
            "Try Again",
            400
        )

    # Generate SHA-256 hash
    uploaded_hash = hashlib.sha256(
        uploaded_bytes
    ).hexdigest()

    # Retrieve original registered paper
    conn = get_db_connection()

    paper = conn.execute(
        """
        SELECT *
        FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    ).fetchone()

    conn.close()

    # Check paper existence
    if paper is None:
        return show_error(
            "Paper Not Found",
            "The selected registered paper was not found.",
            url_for("verify_page"),
            "Back to Verification",
            404
        )

    original_hash = paper["fingerprint"]

    # Default similarity value
    similarity = 0

    # ========================================================
    # EXACT MATCH
    # ========================================================

    if hmac.compare_digest(
        uploaded_hash,
        original_hash
    ):
        result = "EXACT MATCH"

        # Exact match is treated as 100% similarity
        similarity = 100

        result_message = (
            "The suspected paper has exactly the same SHA-256 "
            "fingerprint as the registered paper. "
            "This is treated as a high-risk exact match."
        )

    # ========================================================
    # DIFFERENT HASH: TEXT SIMILARITY CHECK
    # ========================================================

    else:

        temporary_filename = (
            f"verify_{uuid.uuid4().hex}.pdf"
        )

        temporary_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            temporary_filename
        )

        try:
            # Save uploaded file temporarily
            with open(
                temporary_path,
                "wb"
            ) as temporary_file:
                temporary_file.write(uploaded_bytes)

            # Locate original registered PDF
            original_file_path = find_stored_file(paper)

            if original_file_path is None:

                result = "DIFFERENT FILE"

                result_message = (
                    "The fingerprints are different, but the original "
                    "registered PDF could not be located for text comparison."
                )

            else:

                # Extract text from both PDFs
                original_text = extract_pdf_text(
                    original_file_path
                )

                uploaded_text = extract_pdf_text(
                    temporary_path
                )

                # Calculate similarity percentage
                similarity = calculate_text_similarity(
                    original_text,
                    uploaded_text
                )

                # ====================================================
                # RED ZONE: 70% AND ABOVE
                # ====================================================

                if similarity >= 70:

                    result = "MODIFIED COPY DETECTED"

                    result_message = (
                        "The SHA-256 fingerprints are different, "
                        f"but the extracted text is {similarity}% similar. "
                        "This may be a modified copy of the registered paper."
                    )

                # ====================================================
                # YELLOW ZONE: 50% TO 69.999%
                # ====================================================

                elif similarity >= 50:

                    result = "POSSIBLE SIMILARITY"

                    result_message = (
                        "The uploaded paper has a different fingerprint "
                        f"and {similarity}% text similarity with the "
                        "registered paper. Manual checking is recommended."
                    )

                # ====================================================
                # GREEN ZONE: 0% TO 49.999%
                # ====================================================

                else:

                    result = "DIFFERENT FILE"

                    result_message = (
                        "The uploaded paper has a different fingerprint "
                        f"and only {similarity}% text similarity with the "
                        "registered paper."
                    )

        except Exception as error:

            print("VERIFICATION ERROR:", error)

            result = "DIFFERENT FILE"

            result_message = (
                "The files have different fingerprints. "
                "Text comparison could not be completed."
            )

        finally:

            # Delete temporary verification file
            if os.path.exists(temporary_path):
                try:
                    os.remove(temporary_path)

                except OSError:
                    pass

    # ========================================================
    # AUDIT LOG
    # ========================================================

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

    # ========================================================
    # RESULT PAGE
    # ========================================================

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


# ============================================================
# UPLOAD ORIGINAL PAPER
# ============================================================

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
            (
                "Upload rejected non-PDF file "
                f"'{uploaded_file.filename}'."
            )
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
            (
                "Upload rejected invalid PDF file "
                f"'{uploaded_file.filename}'."
            )
        )

        return show_error(
            "Invalid PDF File",
            "The selected file is not recognised as a valid PDF document.",
            url_for("upload_page"),
            "Try Again",
            400
        )

    # Generate fingerprint
    fingerprint = hashlib.sha256(
        file_data
    ).hexdigest()

    # Clean filename
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
            (
                "The selected file has an invalid filename. "
                "Please rename it and try again."
            ),
            url_for("upload_page"),
            "Try Again",
            400
        )

    # Check duplicate fingerprint
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
            (
                f"Duplicate file '{original_filename}' matched "
                f"existing paper '{existing_paper['filename']}'."
            )
        )

        return show_error(
            "Duplicate Paper Detected",
            (
                "This examination paper is already registered. "
                f"Existing filename: {existing_paper['filename']}"
            ),
            url_for("upload_page"),
            "Upload Another Paper",
            400
        )

    # Create unique stored filename
    unique_filename = (
        f"{uuid.uuid4().hex}_{original_filename}"
    )

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_filename
    )

    # Save PDF physically
    try:

        with open(
            file_path,
            "wb"
        ) as saved_file:
            saved_file.write(file_data)

    except OSError as error:

        print("FILE SAVE ERROR:", error)

        add_audit_log(
            "SECURITY EVENT",
            (
                "Server failed to save uploaded file "
                f"'{original_filename}'."
            )
        )

        return show_error(
            "Upload Failed",
            (
                "The server could not save the examination paper. "
                "Please try again."
            ),
            url_for("upload_page"),
            "Try Again",
            500
        )

    # Insert paper record into database
    try:

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO papers
            (
                filename,
                fingerprint,
                uploaded_by,
                uploaded_at,
                stored_filename
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                original_filename,
                fingerprint,
                "Admin",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                unique_filename
            )
        )

        conn.commit()
        conn.close()

    except sqlite3.Error as error:

        print("DATABASE INSERT ERROR:", error)

        if os.path.exists(file_path):
            os.remove(file_path)

        add_audit_log(
            "SECURITY EVENT",
            (
                "Database error occurred while registering "
                f"'{original_filename}'."
            )
        )

        return show_error(
            "Registration Failed",
            "The paper could not be registered in the database.",
            url_for("upload_page"),
            "Try Again",
            500
        )

    # Log successful upload
    add_audit_log(
        "PAPER UPLOADED",
        (
            f"File '{original_filename}' was uploaded "
            "and fingerprinted successfully."
        )
    )

    return redirect(url_for("home"))


# ============================================================
# ADMIN CONTROL
# ============================================================

@app.route("/admin")
def admin_page():

    conn = get_db_connection()

    papers = conn.execute(
        """
        SELECT *
        FROM papers
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        papers=papers
    )


# ============================================================
# DELETE PAPER
# ============================================================

@app.route("/delete-paper/<int:paper_id>", methods=["POST"])
def delete_paper(paper_id):

    conn = get_db_connection()

    paper = conn.execute(
        """
        SELECT *
        FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    ).fetchone()

    if paper is None:

        conn.close()

        add_audit_log(
            "SECURITY EVENT",
            (
                "Deletion attempted for non-existent "
                f"paper ID {paper_id}."
            )
        )

        return show_error(
            "Paper Not Found",
            "The selected examination paper does not exist.",
            url_for("admin_page"),
            "Back to Admin",
            404
        )

    stored_path = find_stored_file(paper)

    conn.execute(
        """
        DELETE FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()
    conn.close()

    # Delete physical PDF
    if stored_path and os.path.exists(stored_path):

        try:
            os.remove(stored_path)

        except OSError as error:
            print("FILE DELETE ERROR:", error)

    add_audit_log(
        "PAPER DELETED",
        (
            f"Registered paper '{paper['filename']}' "
            f"with ID {paper_id} was deleted by Admin."
        )
    )

    return redirect(url_for("admin_page"))


# ============================================================
# AUDIT TRAIL
# ============================================================

@app.route("/audit-trail")
def audit_trail():

    conn = get_db_connection()

    audit_logs = conn.execute(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        """
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

    print("INTERNAL SERVER ERROR:", error)

    return show_error(
        "Server Error",
        "An unexpected error occurred while processing the request.",
        url_for("home"),
        "Back to Dashboard",
        500
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)