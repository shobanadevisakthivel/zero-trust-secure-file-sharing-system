import os
import json
import re
from datetime import datetime, timedelta

from dotenv import load_dotenv

# ==========================================================
# LOAD .ENV
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# ==========================================================
# FLASK
# ==========================================================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    jsonify,
    abort,
)

from werkzeug.security import check_password_hash

from config import DATABASE, SECRET_KEY
from database import db

from database.models import (
    User,
    File,
    AuditLog,
    RiskScore,
    FilePermission,
    LoginHistory,
    ThreatAlert,
)

from modules.auth import verify_user, create_user
from modules.file_manager import save_uploaded_file
from modules.access_control import give_permission
from modules.download_manager import view_secure_file
from modules.audit_logger import create_audit_log

# ==========================================================
# OPENAI
# ==========================================================

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ==========================================================
# FLASK APPLICATION
# ==========================================================

app = Flask(__name__, template_folder="templates")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = SECRET_KEY

db.init_app(app)

# ==========================================================
# AI CONFIGURATION
# ==========================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
AI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna").strip()

print("==========================================")
print("AI CONFIGURATION")
print("==========================================")
print("OPENAI_API_KEY:", "LOADED" if OPENAI_API_KEY else "NOT LOADED")
print("OPENAI_MODEL:", AI_MODEL)
print("==========================================")

# ==========================================================
# SECURITY CONFIGURATION
# ==========================================================

MAX_VIEWER_VIOLATIONS = 3
BLOCK_DURATION_HOURS = 2
VIOLATION_WINDOW_MINUTES = 5
SECURITY_ACTIONS = [


    "COPY_ATTEMPT",
    "SAVE_ATTEMPT",
    "PRINT_ATTEMPT",
    "RIGHT_CLICK_ATTEMPT",
    "SCREENSHOT_ATTEMPT",
    "TAB_SWITCH_ATTEMPT",
]

MAX_RISK_SCORE = 90

# ==========================================================
# HOME
# ==========================================================

@app.route("/")
def home():
    return "Secure File Sharing System Running"

# ==========================================================
# CREATE USERS
# ==========================================================

@app.route("/create-users")
def create_users():
    with app.app_context():
        existing_users = {user.username for user in User.query.all()}
        created = []

        if "Alice" not in existing_users:
            create_user("Alice", "alice123", "owner")
            created.append("Alice")

        if "Bob" not in existing_users:
            create_user("Bob", "bob123", "authorized")
            created.append("Bob")

        if "Charlie" not in existing_users:
            create_user("Charlie", "charlie123", "unauthorized")
            created.append("Charlie")

        if "David" not in existing_users:
            create_user("David", "david123", "authorized")
            created.append("David")

        db.session.commit()

        if created:
            return "Users created successfully: " + ", ".join(created)

        return "Users Already Exist"

# ==========================================================
# LOGIN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)

        if user:
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            return redirect("/dashboard")

        return "Invalid Login"

    return render_template("login.html")

# ==========================================================
# CURRENT USER
# ==========================================================

def get_current_user():
    username = session.get("username")
    if not username:
        return None

    return User.query.filter_by(username=username).first()

# ==========================================================
# DASHBOARD
# ==========================================================

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")

    user = get_current_user()

    if not user:
        session.clear()


        return redirect("/login")

    files = File.query.filter_by(owner_id=user.id).all()

    permissions = FilePermission.query.filter_by(
        username=user.username
    ).all()

    shared_files = []

    for permission in permissions:
        shared_file = File.query.get(permission.file_id)

        if shared_file and shared_file not in files:
            shared_files.append(shared_file)

    total_events = AuditLog.query.filter_by(
        username=user.username
    ).count()

    blocked_attempts = AuditLog.query.filter_by(
        username=user.username,
        status="BLOCKED",
    ).count()

    file_views = AuditLog.query.filter_by(
        username=user.username,
        action="SECURE FILE VIEW",
    ).count()

    threat_alerts = AuditLog.query.filter(
        AuditLog.username == user.username,
        AuditLog.status == "BLOCKED",
        AuditLog.action.in_(SECURITY_ACTIONS),
    ).count()

    security_score = 100 - (blocked_attempts * 5)
    security_score = max(0, min(100, security_score))

    return render_template(
        "dashboard.html",
        username=user.username,
        role=user.role,
        risk_score=user.risk_score or 0,
        file_count=len(files) + len(shared_files),
        files=files,
        shared_files=shared_files,
        total_events=total_events,
        blocked_attempts=blocked_attempts,
        file_views=file_views,
        threat_alerts=threat_alerts,
        security_score=security_score,
    )

# ==========================================================
# DELETE FILE
# ==========================================================

@app.route("/files/<int:file_id>/delete", methods=["POST"])
def delete_file(file_id):
    if "username" not in session:
        return redirect("/login")

    user = get_current_user()

    if not user:
        session.clear()
        return redirect("/login")

    file = db.session.get(File, file_id)

    if not file:
        return ("File not found.", 404)

    if file.owner_id != user.id:
        create_audit_log(
            username=user.username,
            action="UNAUTHORIZED FILE DELETE ATTEMPT",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="BLOCKED",
        )
        return ("You are not authorized to delete this file.", 403)

    encrypted_path = os.path.abspath(
        os.path.join(BASE_DIR, file.encrypted_path)
    )
    encrypted_folder = os.path.abspath(
        os.path.join(BASE_DIR, "storage", "encrypted_files")
    )

    try:
        if os.path.commonpath([encrypted_folder, encrypted_path]) != encrypted_folder:
            raise ValueError("Invalid encrypted file path")

        if os.path.isfile(encrypted_path):
            os.remove(encrypted_path)


        FilePermission.query.filter_by(file_id=file.id).delete()
        filename_for_audit = file.filename
        db.session.delete(file)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print("File deletion error:", e)
        return ("Unable to delete the file.", 500)

    create_audit_log(
        username=user.username,
        action="FILE DELETED",
        filename=filename_for_audit,
        ip_address=request.remote_addr,
        device=request.headers.get("User-Agent", "Unknown Device"),
        status="SUCCESS",
    )

    return redirect("/dashboard")

# ==========================================================
# VIEW FILE ID - SECURE OWNER PASSWORD VERIFICATION
# ==========================================================

@app.route("/verify-file-id/<int:file_id>", methods=["POST"])
def verify_file_id(file_id):
    if "username" not in session:
        return jsonify({
            "success": False,
            "message": "Authentication required.",
        }), 401

    user = get_current_user()

    if not user:
        session.clear()
        return jsonify({
            "success": False,
            "message": "Authentication required.",
        }), 401

    file = db.session.get(File, file_id)

    if not file:
        try:
            create_audit_log(
                username=user.username,
                action="FILE ID ACCESS ATTEMPT",
                filename="-",
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),
                status="BLOCKED",
            )
        except Exception as e:
            print("File ID audit error:", e)

        return jsonify({
            "success": False,
            "message": "Access Denied - incorrect password or unauthorized file.",
        }), 403

    if file.owner_id != user.id:
        try:
            create_audit_log(
                username=user.username,
                action="UNAUTHORIZED FILE ID ACCESS",
                filename=file.filename,
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),
                status="BLOCKED",
            )
        except Exception as e:
            print("Unauthorized File ID audit error:", e)

        return jsonify({
            "success": False,
            "message": "Access Denied - incorrect password or unauthorized file.",
        }), 403

    password = request.form.get("password", "")

    if not password:
        try:
            data = request.get_json(silent=True)
            if data:
                password = data.get("password", "")
        except Exception:
            pass

    if not password:
        try:
            create_audit_log(
                username=user.username,
                action="FILE ID PASSWORD VERIFICATION FAILED",
                filename=file.filename,
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),


                status="BLOCKED",
            )
        except Exception as e:
            print("Password verification audit error:", e)

        return jsonify({
            "success": False,
            "message": "Login password is required.",
        }), 403

    password_valid = False

    try:
        password_valid = check_password_hash(user.password, password)
    except Exception as e:
        print("Password verification error:", e)

    if not password_valid:
        try:
            create_audit_log(
                username=user.username,
                action="FILE ID PASSWORD VERIFICATION FAILED",
                filename=file.filename,
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),
                status="BLOCKED",
            )
        except Exception as e:
            print("Failed File ID audit error:", e)

        return jsonify({
            "success": False,
            "message": "Access Denied - incorrect password or unauthorized file.",
        }), 403

    try:
        create_audit_log(
            username=user.username,
            action="FILE ID RETRIEVED",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="SUCCESS",
        )
    except Exception as e:
        print("Successful File ID audit error:", e)

    return jsonify({
        "success": True,
        "file_id": file.id,
        "message": "File ID verified successfully.",
    }), 200

# ==========================================================
# UPLOAD
# ==========================================================

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")

    user = get_current_user()

    if not user:
        session.clear()
        return redirect("/login")

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file:
            return ("No file selected", 400)

        if not uploaded_file.filename:
            return ("Invalid filename", 400)

        try:
            save_uploaded_file(uploaded_file, user)
            return "File Uploaded Successfully"
        except Exception as e:
            print("Upload Error:", e)
            return ("File upload failed.", 500)

    return render_template("upload.html")

# ==========================================================
# SHARE FILE
# ==========================================================

@app.route("/share", methods=["GET", "POST"])
def share():
    if "user_id" not in session:
        return redirect("/login")

    user = get_current_user()

    if not user:


        session.clear()
        return redirect("/login")

    if request.method == "GET":
        owned_files = File.query.filter_by(owner_id=user.id).all()
        users = User.query.filter(User.id != user.id).order_by(User.username.asc()).all()
        return render_template("share_file.html", files=owned_files, users=users)

    file_id = request.form.get("file_id")
    username = request.form.get("username")

    if not file_id or not username:
        return ("File ID and username are required.", 400)

    try:
        file_id_int = int(file_id)
    except (TypeError, ValueError):
        return ("Invalid file ID.", 400)

    file = db.session.get(File, file_id_int)

    if not file:
        return ("File not found", 404)

    if file.owner_id != user.id:
        create_audit_log(
            username=user.username,
            action="UNAUTHORIZED SHARE ATTEMPT",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="BLOCKED",
        )
        return ("You are not authorized to share this file.", 403)

    target_user = User.query.filter_by(username=username).first()

    if not target_user:
        return ("User not found", 404)

    if target_user.id == user.id:
        return ("You cannot share a file with yourself.", 400)

    try:
        give_permission(file_id_int, username)

        create_audit_log(
            username=user.username,
            action="FILE SHARED",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="SUCCESS",
        )

        return "Permission Granted Successfully"

    except Exception as e:
        print("Share Error:", e)
        return ("Unable to share the file.", 500)

# ==========================================================
# ZERO TRUST FILE ACCESS
# ==========================================================

def user_can_access_file(file_id, username):
    file = db.session.get(File, file_id)

    if not file:
        return False, None

    if file.owner and file.owner.username == username:
        return True, file

    permission = FilePermission.query.filter_by(
        file_id=file_id,
        username=username,
    ).first()

    if permission:
        return True, file

    return False, file

# ==========================================================
# VIEWER SESSION
# ==========================================================

def reset_viewer_session():
    session["viewer_violation_count"] = 0
    session["viewer_locked"] = False
    session.pop("secure_view_block_until", None)

# ==========================================================
# ACTIVE BLOCK
# ==========================================================

def get_active_block_time():


    block_until = session.get("secure_view_block_until")

    if not block_until:
        return None

    try:
        block_time = datetime.fromisoformat(block_until)
    except Exception:
        session.pop("secure_view_block_until", None)
        return None

    if datetime.utcnow() >= block_time:
        session.pop("secure_view_block_until", None)
        session["viewer_locked"] = False
        session["viewer_violation_count"] = 0
        return None

    return block_time

# ==========================================================
# SECURE VIEWER
# ==========================================================

@app.route("/secure-view/<int:file_id>")
def secure_view(file_id):
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user = get_current_user()

    if not user:
        session.clear()
        return redirect("/login")

    active_block = get_active_block_time()

    if active_block:
        remaining = active_block - datetime.utcnow()
        total_seconds = max(0, int(remaining.total_seconds()))
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60

        return render_template(
            "secure_view.html",
            pages=[],
            username=username,
            ip=request.remote_addr,
            blocked=True,
            blocked_hours=hours,
            blocked_minutes=minutes,
        )

    allowed, file = user_can_access_file(file_id, username)

    if not allowed:
        create_audit_log(
            username=username,
            action="UNAUTHORIZED FILE ACCESS",
            filename=file.filename if file else "-",
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="BLOCKED",
        )

        return """
<!DOCTYPE html>
<html>
<head>
<title>Access Denied</title>
<style>
body {
      background:#050b18;
      color:white;
      font-family:Segoe UI,sans-serif;
      text-align:center;
      padding-top:120px;
}
h1 {
      color:#ff4d6d;
      font-size:42px;
}
p {
      font-size:20px;
      color:#b8c7d9;
}
</style>
</head>
<body>
<h1>ACCESS DENIED</h1>
<p>Zero Trust Policy Blocked This Request</p>
<p>You do not have permission to view this file.</p>
</body>
</html>
""", 403

    # A new secure viewer request starts a fresh in-session violation count.
    session["viewer_violation_count"] = 0


    session["viewer_locked"] = False

    try:
        pages = view_secure_file(file_id, username)
    except Exception as e:
        print("Secure Viewer Error:", e)
        return ("Unable to open secure viewer.", 500)

    if not pages:
        create_audit_log(
            username=username,
            action="SECURE VIEW DENIED",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="BLOCKED",
        )

        return """
<h2>ACCESS DENIED</h2>
<p>Zero Trust Policy Blocked This Request</p>
""", 403

    try:
        create_audit_log(
            username=username,
            action="SECURE FILE VIEW",
            filename=file.filename,
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="SUCCESS",
        )
    except Exception as e:
        print("View audit error:", e)

    image_list = []

    for page in pages:
        page = page.replace("\\", "/")
        image_list.append("/secure-page/" + page)

    return render_template(
        "secure_view.html",
        pages=image_list,
        username=username,
        ip=request.remote_addr,
        blocked=False,
        blocked_hours=0,
        blocked_minutes=0,
    )

# ==========================================================
# SECURE PAGE IMAGES
# ==========================================================

@app.route("/secure-page/<path:path>")
def secure_page(path):
    if "username" not in session:
        return redirect("/login")

    if not path:
        abort(404)

    normalized_path = os.path.normpath(path)

    if os.path.isabs(normalized_path) or normalized_path.startswith(".."):
        abort(403)

    candidate_path = os.path.abspath(
        os.path.join(BASE_DIR, normalized_path)
    )

    try:
        allowed_base = os.path.abspath(BASE_DIR)
        if os.path.commonpath([allowed_base, candidate_path]) != allowed_base:
            abort(403)
        return send_file(candidate_path)
    except Exception as e:
        print("Secure page error:", e)
        abort(404)

# ==========================================================
# SECURITY VIOLATION
# ==========================================================

@app.route("/security-violation/<action>", methods=["POST"])
def security_violation(action):
    try:
        username = session.get("username")

        if not username:
            return jsonify({
                "status": "denied",
                "message": "Authentication required.",
            }), 401

        if action not in SECURITY_ACTIONS:
            return jsonify({"status": "invalid"}), 400


        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "Unknown")

        active_block = get_active_block_time()

        if active_block:
            return jsonify({
                "status": "locked",
                "message": "Security block is active.",
                "blocked_until": active_block.isoformat(),
            })

        create_audit_log(
            username=username,
            action=action,
            filename="Secure Viewer",
            ip_address=ip_address,
            device=user_agent,
            status="BLOCKED",
        )

        count = session.get("viewer_violation_count", 0) + 1
        session["viewer_violation_count"] = count

        print("CURRENT VIEWER VIOLATION COUNT:", count)

        if count >= MAX_VIEWER_VIOLATIONS:
            block_until = datetime.utcnow() + timedelta(
                hours=BLOCK_DURATION_HOURS
            )

            session["secure_view_block_until"] = block_until.isoformat()
            session["viewer_locked"] = True

            create_audit_log(
                username=username,
                action="SECURE VIEWER LOCKED",
                filename="Secure Viewer",
                ip_address=ip_address,
                device=user_agent,
                status="BLOCKED",
            )

            return jsonify({
                "status": "locked",
                "count": count,
                "blocked_until": block_until.isoformat(),
                "message": (
                    "Multiple security violations detected. "
                    "Secure viewer locked."
                ),
            })

        remaining = MAX_VIEWER_VIOLATIONS - count

        return jsonify({
            "status": "logged",
            "count": count,
            "remaining": remaining,
            "message": "Security violation recorded.",
        })

    except Exception as e:
        print("Security Event Error:", e)
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500

# ==========================================================
# AUDIT LOGS
# ==========================================================

@app.route("/audit-logs")
def audit_logs():
    if "username" not in session:
        return redirect("/login")

    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
    return render_template("audit_logs.html", logs=logs)

# ==========================================================
# RISK ANALYSIS
# ==========================================================

@app.route("/risk-analysis")
def risk_analysis():
    if "username" not in session:
        return redirect("/login")

    try:
        all_users = User.query.order_by(User.id.asc()).all()
        risk_data = []
        risk_history_by_user = {}
        risk_chart_data = []

        for user in all_users:
            username = user.username


            audit_logs = AuditLog.query.filter_by(
                username=username
            ).all()

            blocked_attempts = 0
            unauthorized_access = 0
            security_violations = 0
            suspicious_activity = 0
            secure_views = 0

            for log in audit_logs:
                action = (log.action or "").upper()
                status = (log.status or "").upper()

                if status == "BLOCKED":
                    blocked_attempts += 1

                    if (
                            "UNAUTHORIZED" in action
                            or "ACCESS DENIED" in action
                            or "DENIED" in action
                        ):
                            unauthorized_access += 1

                    if action in SECURITY_ACTIONS:
                            security_violations += 1

                    if (
                            "SUSPICIOUS" in action
                            or "MALWARE" in action
                            or "ATTACK" in action
                            or "THREAT" in action
                        ):
                            suspicious_activity += 1

                if action == "SECURE FILE VIEW":
                    secure_views += 1

            login_history = LoginHistory.query.filter_by(
                username=username
            ).all()

            failed_logins = 0
            successful_logins = 0
            known_devices = set()
            new_device_events = 0

            for login_record in login_history:
                status = (login_record.status or "").upper()
                device = (login_record.device or "").strip()

                if (
                        status == "FAILED"
                        or status == "BLOCKED"
                        or "FAIL" in status
                ):
                    failed_logins += 1
                elif status == "SUCCESS" or "SUCCESS" in status:
                    successful_logins += 1

                if device:
                    if device not in known_devices and known_devices:
                        new_device_events += 1
                    known_devices.add(device)

            threat_alerts = ThreatAlert.query.filter_by(
                username=username
            ).all()

            critical_alerts = 0
            high_alerts = 0
            medium_alerts = 0
            low_alerts = 0

            for alert in threat_alerts:
                severity = (alert.severity or "").upper()

                if severity == "CRITICAL":
                    critical_alerts += 1
                elif severity == "HIGH":
                    high_alerts += 1
                elif severity == "MEDIUM":
                    medium_alerts += 1
                elif severity == "LOW":
                    low_alerts += 1

            calculated_score = (
                min(50, critical_alerts * 25)
                + min(30, high_alerts * 15)
                + min(24, medium_alerts * 8)
                + min(10, low_alerts * 2)
                + min(30, unauthorized_access * 10)
                + min(50, security_violations * 1.25)
                + min(12, failed_logins * 3)
                + min(9, new_device_events * 3)
                + min(15, suspicious_activity * 5)
            )
            score = max(0, min(MAX_RISK_SCORE, round(calculated_score)))


            level = _risk_level(score)
            reasons = []

            if critical_alerts > 0:
                reasons.append(f"{critical_alerts} critical threat alert(s)")
            if high_alerts > 0:
                reasons.append(f"{high_alerts} high-severity threat alert(s)")
            if medium_alerts > 0:
                reasons.append(f"{medium_alerts} medium-severity threat alert(s)")
            if low_alerts > 0:
                reasons.append(f"{low_alerts} low-severity threat alert(s)")
            if unauthorized_access > 0:
                reasons.append(f"{unauthorized_access} unauthorized access attempt(s)")
            if security_violations > 0:
                reasons.append(f"{security_violations} security violation(s)")
            if failed_logins > 0:
                reasons.append(f"{failed_logins} failed login attempt(s)")
            if new_device_events > 0:
                reasons.append(f"{new_device_events} new device event(s)")
            if suspicious_activity > 0:
                reasons.append(f"{suspicious_activity} suspicious activity event(s)")

            reason = (
                ", ".join(reasons)
                if reasons
                else "No significant security threats detected from current activity"
            )

            user.risk_score = score
            updated_time = datetime.now()

            risk_history_by_user[username] = [{
                "id": None,
                "username": username,
                "score": score,
                "risk_score": score,
                "reason": reason,
                "updated_time": str(updated_time),
            }]

            risk_data.append({
                "id": user.id,
                "username": username,
                "score": score,
                "risk_score": score,
                "reason": reason,
                "level": level,
                "updated_time": str(updated_time),
                "history": risk_history_by_user[username],
                "audit_events": len(audit_logs),
                "blocked_attempts": blocked_attempts,
                "unauthorized_access": unauthorized_access,
                "security_violations": security_violations,
                "failed_logins": failed_logins,
                "successful_logins": successful_logins,
                "new_device_events": new_device_events,
                "threat_alerts": len(threat_alerts),
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "low_alerts": low_alerts,
                "suspicious_activity": suspicious_activity,
                "secure_views": secure_views,
            })

            threat_score = min(
                100,
                critical_alerts * 30
                + high_alerts * 20
                + medium_alerts * 10
                + low_alerts * 3,
            )

            risk_chart_data.append({
                "username": username,
                "labels": [
                    "Audit Logs",
                    "Login History",
                    "Threat Alerts",
                    "Final Risk",
                ],
                "scores": [
                    min(100, blocked_attempts * 5),
                    min(100, failed_logins * 5),
                    threat_score,
                    score,
                ],
                "reasons": [
                    f"{blocked_attempts} blocked audit event(s)",
                    f"{failed_logins} failed login(s)",
                    f"{len(threat_alerts)} threat alert(s)",
                    reason,
                ],
                "record_ids": [],
            })

        db.session.commit()
        risk_data.sort(key=lambda item: item["score"], reverse=True)


        risk_chart_json = json.dumps(risk_chart_data, default=str)

        current_user = get_current_user()
        current_score = current_user.risk_score if current_user else 0
        current_score = max(0, min(100, current_score))
        risk_level = _risk_level(current_score)

        scores = [item["score"] for item in risk_data]
        users_assessed = len(risk_data)

        if scores:
            average_risk = round(sum(scores) / len(scores))
            highest_item = max(risk_data, key=lambda item: item["score"])
            highest_risk_user = highest_item["username"]
            highest_risk_score = highest_item["score"]
        else:
            average_risk = 0
            highest_risk_user = "None"
            highest_risk_score = 0

        low_count = 0
        medium_count = 0
        high_count = 0
        critical_count = 0

        for item in risk_data:
            score = item["score"]
            if score >= 80:
                critical_count += 1
            elif score >= 60:
                high_count += 1
            elif score >= 30:
                medium_count += 1
            else:
                low_count += 1

        return render_template(
            "risk_analysis.html",
            username=session.get("username", ""),
            role=session.get("role", ""),
            users=risk_data,
            risks=risk_data,
            risk_score=current_score,
            risk_level=risk_level,
            average_risk=average_risk,
            highest_risk_user=highest_risk_user,
            highest_risk_score=highest_risk_score,
            users_assessed=users_assessed,
            low_count=low_count,
            medium_count=medium_count,
            high_count=high_count,
            critical_count=critical_count,
            risk_history_by_user=risk_history_by_user,
            risk_chart_data=risk_chart_data,
            risk_chart_json=risk_chart_json,
        )

    except Exception as e:
        db.session.rollback()
        print("Risk Analysis Error:", e)

        return render_template(
            "risk_analysis.html",
            username=session.get("username", ""),
            role=session.get("role", ""),
            users=[],
            risks=[],
            risk_score=0,
            risk_level="LOW",
            average_risk=0,
            highest_risk_user="None",
            highest_risk_score=0,
            users_assessed=0,
            low_count=0,
            medium_count=0,
            high_count=0,
            critical_count=0,
            risk_history_by_user={},
            risk_chart_data=[],
            risk_chart_json="[]",
        )

# ==========================================================
# REPORTS
# ==========================================================

@app.route("/reports")
def reports():
    if "username" not in session:
        return redirect("/login")

    try:
        from modules.reports import generate_report
        report = generate_report()
    except Exception as e:
        print("Reports Error:", e)
        report = {"error": "Unable to generate security report."}
    return render_template("reports.html", report=report)


# ==========================================================
# THREAT ANALYSIS ENGINE
# ==========================================================

def generate_threat_analysis(
    critical_threats,
    high_threats,
    medium_threats,
    low_threats,
    active_threats,
    resolved_threats,
    security_alerts,
    monitored_events,
    unauthorized_access,
    suspicious_behaviour,
    repeated_violations,
    abnormal_file_access,
    malware_threats,
):
    if critical_threats > 0:
        analysis = (
            f"The monitoring system detected {critical_threats} critical security event"
            + ("" if critical_threats == 1 else "s")
            + ". "
        )

        if unauthorized_access > 0:
            analysis += (
                f"{unauthorized_access} unauthorized access event"
                + ("" if unauthorized_access == 1 else "s")
                + " were recorded. "
            )

        if malware_threats > 0:
            analysis += (
                f"{malware_threats} malware-related event"
                + ("" if malware_threats == 1 else "s")
                + " were detected. "
            )

        if repeated_violations > 0:
            analysis += (
                "Repeated security violations were also observed, "
                "indicating elevated security risk. "
            )

        analysis += "Immediate security review is recommended."

        return {
            "status": "critical",
            "title": "CRITICAL THREAT ACTIVITY",
            "analysis": analysis,
        }

    if high_threats > 0:
        analysis = (
            f"The monitoring system detected {high_threats} high-severity security event"
            + ("" if high_threats == 1 else "s")
            + ". "
        )

        if suspicious_behaviour > 0:
            analysis += (
                f"{suspicious_behaviour} suspicious security interaction"
                + ("" if suspicious_behaviour == 1 else "s")
                + " were recorded. "
            )

        if repeated_violations > 0:
            analysis += (
                "Repeated violations indicate a pattern that requires attention. "
            )

        analysis += (
            "The activity should be reviewed by the security administrator."
        )

        return {
            "status": "high",
            "title": "HIGH THREAT ACTIVITY",
            "analysis": analysis,
        }

    if medium_threats > 0:
        analysis = (
            f"The monitoring system detected {medium_threats} medium-severity security event"
            + ("" if medium_threats == 1 else "s")
            + ". "
        )

        if abnormal_file_access > 0:
            analysis += (
                f"{abnormal_file_access} file-access-related event"
                + ("" if abnormal_file_access == 1 else "s")
                + " were recorded. "
            )

        analysis += (


            "The current activity should continue to be monitored for escalation."
        )

        return {
            "status": "medium",
            "title": "MODERATE THREAT ACTIVITY",
            "analysis": analysis,
        }

    if low_threats > 0:
        return {
            "status": "low",
            "title": "LOW THREAT ACTIVITY",
            "analysis": (
                f"The monitoring system recorded {low_threats} low-severity security event"
                + ("" if low_threats == 1 else "s")
                + ". No critical or high-severity threat is currently identified."
            ),
        }

    return {
        "status": "normal",
        "title": "NO SIGNIFICANT THREAT ACTIVITY",
        "analysis": (
            "The monitoring system has not detected any significant security threat "
            "events in the available audit data."
        ),
    }

# ==========================================================
# THREAT DATA CALCULATOR
# ==========================================================

def get_threat_statistics():
    critical_threats = 0
    high_threats = 0
    medium_threats = 0
    low_threats = 0

    unauthorized_access = 0
    suspicious_behaviour = 0
    repeated_violations = 0
    abnormal_file_access = 0
    malware_threats = 0

    all_events = [
        log for log in AuditLog.query.all()
        if not _is_ai_bookkeeping_log(log)
    ]
    blocked_events = [
        log for log in all_events
        if str(getattr(log, "status", "") or "").upper() == "BLOCKED"
    ]

    monitored_events = len(all_events)
    # Security alerts in this project are real blocked/security events.
    security_alerts = len(blocked_events)

    for log in all_events:
        action = (log.action or "").upper()

        if "UNAUTHORIZED" in action or "ACCESS DENIED" in action:
            unauthorized_access += 1

        if action in SECURITY_ACTIONS:
            suspicious_behaviour += 1

        if "SECURE VIEWER LOCKED" in action or "REPEATED" in action:
            repeated_violations += 1

        if (
            "FILE ACCESS" in action
            or "SECURE VIEW" in action
            or "FILE VIEW" in action
        ):
            abnormal_file_access += 1

        if "MALWARE" in action:
            malware_threats += 1

    for log in blocked_events:
        action = (log.action or "").upper()

        if (
            "UNAUTHORIZED FILE ACCESS" in action
            or "SECURE VIEWER LOCKED" in action
            or "MALWARE" in action
        ):
            critical_threats += 1
        elif action in SECURITY_ACTIONS:
            high_threats += 1
        elif "ACCESS" in action or "SHARE" in action or "DENIED" in action:
            medium_threats += 1
        else:
            low_threats += 1

    return {
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "active_threats": critical_threats + high_threats,
        "resolved_threats": medium_threats + low_threats,


        "security_alerts": security_alerts,
        "monitored_events": monitored_events,
        "unauthorized_access": unauthorized_access,
        "suspicious_behaviour": suspicious_behaviour,
        "repeated_violations": repeated_violations,
        "abnormal_file_access": abnormal_file_access,
        "malware_threats": malware_threats,
    }

# ==========================================================
# THREAT MONITORING
# ==========================================================

@app.route("/threat_monitoring")
def threat_monitoring():
    if "username" not in session:
        return redirect("/login")

    username = session.get("username")
    user = get_current_user()

    if not user:
        session.clear()
        return redirect("/login")

    try:
        statistics = get_threat_statistics()
    except Exception as e:
        print("Threat Monitoring Error:", e)
        statistics = {
            "critical_threats": 0,
            "high_threats": 0,
            "medium_threats": 0,
            "low_threats": 0,
            "active_threats": 0,
            "resolved_threats": 0,
            "security_alerts": 0,
            "monitored_events": 0,
            "unauthorized_access": 0,
            "suspicious_behaviour": 0,
            "repeated_violations": 0,
            "abnormal_file_access": 0,
            "malware_threats": 0,
        }

    ai_result = generate_threat_analysis(**statistics)

    return render_template(
        "threat_monitoring.html",
        username=username,
        role=user.role,
        **statistics,
        ai_threat_analysis=ai_result["analysis"],
        ai_threat_title=ai_result["title"],
        ai_threat_status=ai_result["status"],
    )

# ==========================================================
# THREAT ANALYSIS API
# ==========================================================

@app.route("/api/threat-analysis", methods=["GET", "POST"])
def threat_analysis_api():
    if "username" not in session:
        return jsonify({
            "status": "denied",
            "message": "Authentication required.",
        }), 401

    try:
        statistics = get_threat_statistics()
        result = generate_threat_analysis(**statistics)

        return jsonify({
            "status": "success",
            "analysis_status": result["status"],
            "title": result["title"],
            "analysis": result["analysis"],
            **statistics,
        })

    except Exception as e:
        print("Threat Analysis API Error:", e)
        return jsonify({
            "status": "error",
            "message": "Unable to generate threat analysis.",
        }), 500

# ==========================================================
# AUTHORIZED FILES
# ==========================================================

def get_authorized_files(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return []
    authorized_files = []


    owned_files = File.query.filter_by(owner_id=user.id).all()
    authorized_files.extend(owned_files)

    permissions = FilePermission.query.filter_by(
        username=username
    ).all()

    for permission in permissions:
        file = db.session.get(File, permission.file_id)

        if file and file not in authorized_files:
            authorized_files.append(file)

    return authorized_files

# ==========================================================
# FILE QUESTION DETECTION
# ==========================================================

def looks_like_file_question(message):
    text = str(message or "").lower()

    keywords = [
        "summarize",
        "summarise",
        "summary",
        "document",
        "file",
        "pdf",
        "project.pdf",
        "important points",
        "explain this document",
        "what does this file contain",
        "find information",
        "contents of",
        "content of",
        "what does the file say",
        "what does this say",
        "read the file",
        "explain the file",
    ]

    return any(keyword in text for keyword in keywords)

# ==========================================================
# FIND REQUESTED FILE
# ==========================================================

def find_requested_file(message, username):
    authorized_files = get_authorized_files(username)
    text = str(message or "").lower()

    for file in authorized_files:
        filename = (file.filename or "").lower()

        if filename and filename in text:
            return file

    if len(authorized_files) == 1 and looks_like_file_question(message):
        return authorized_files[0]

    return None

# ==========================================================
# SECURITY CONTEXT HELPERS
# ==========================================================

def _safe_datetime_value(value):
    if value is None:
        return None

    try:
        return value.isoformat(sep=" ")
    except Exception:
        return str(value)


def _record_time(record, *field_names):
    for field_name in field_names:
        value = getattr(record, field_name, None)
        if value is not None:
            return value
    return None


def _risk_level(score):
    try:
        score = float(score or 0)
    except Exception:
        score = 0

    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _risk_record_to_dict(record):
    """Expose a RiskScore record safely, supporting score/risk_score models."""
    score = getattr(record, "score", None)

    if score is None:
        score = getattr(record, "risk_score", 0)

    try:
        score = float(score or 0)
    except Exception:
        score = 0

    return {
        "id": getattr(record, "id", None),
        "username": getattr(record, "username", None),
        "score": score,
        "risk_score": score,
        "level": _risk_level(score),
        "risk_level": _risk_level(score),
        "reason": getattr(record, "reason", None),
        "updated_time": _safe_datetime_value(
            _record_time(
                record,
                "updated_time",
                "timestamp",
                "created_at",
                "created_on",
            )
        ),
    }


def _audit_record_to_dict(log):
    return {
        "id": getattr(log, "id", None),
        "username": getattr(log, "username", None),
        "action": getattr(log, "action", None),
        "status": getattr(log, "status", None),
        "filename": getattr(log, "filename", None),
        "ip": getattr(log, "ip_address", None),
        "device": getattr(log, "device", None),
        "timestamp": _safe_datetime_value(
            _record_time(log, "timestamp", "created_at", "updated_time")
        ),
    }


def _login_record_to_dict(login):
    return {
        "id": getattr(login, "id", None),
        "username": getattr(login, "username", None),
        "status": getattr(login, "status", None),
        "device": getattr(login, "device", None),
        "ip": getattr(login, "ip_address", None),
        "timestamp": _safe_datetime_value(
            _record_time(login, "timestamp", "created_at", "updated_time")
        ),
    }


def _threat_record_to_dict(alert):
    return {
        "id": getattr(alert, "id", None),
        "username": getattr(alert, "username", None),
        "severity": getattr(alert, "severity", None),
        "type": (
            getattr(alert, "threat_type", None)
            or getattr(alert, "alert_type", None)
            or getattr(alert, "type", None)
        ),
        "description": (
            getattr(alert, "description", None)
            or getattr(alert, "message", None)
        ),
        "status": getattr(alert, "status", None),
        "timestamp": _safe_datetime_value(
            _record_time(alert, "timestamp", "created_at", "updated_time")
        ),
    }


def _parse_record_datetime(record):
    value = _record_time(
        record,
        "timestamp",
        "updated_time",
        "created_at",
        "created_on",
    )

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.replace(tzinfo=None)

    try:
        parsed = datetime.fromisoformat(


            str(value).replace("Z", "+00:00")
        )
        return parsed.replace(tzinfo=None)
    except Exception:
        return None

# ==========================================================
# HISTORICAL RISK DATA
# ==========================================================

def _build_historical_risk_data():
    """
     Build a complete historical risk view from ALL RiskScore records.
     This is deliberately not limited to the latest score.
     """
    records = RiskScore.query.order_by(RiskScore.id.asc()).all()

    history = {}

    for record in records:
        username = getattr(record, "username", None)

        if not username:
            continue

        history.setdefault(username, []).append(
            _risk_record_to_dict(record)
        )

    return history


# ==========================================================
# AI DATA HELPERS
# ==========================================================

def _is_ai_bookkeeping_log(log):
    """Return True for assistant bookkeeping records, not real security events."""
    action = str(getattr(log, "action", "") or "").upper().strip()
    return action in {
        "AI SECURITY ASSISTANT QUERY",
        "AI INAPPROPRIATE QUESTION",
        "AI FILE INFORMATION REQUEST",
    }


def _get_authorized_file_ids(username):
    """Return the unique file IDs this user is allowed to access."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return set()

    file_ids = {
        file.id
        for file in File.query.filter_by(owner_id=user.id).all()
    }

    permissions = FilePermission.query.filter_by(
        username=username
    ).all()

    for permission in permissions:
        if permission.file_id is not None:
            file_ids.add(permission.file_id)

    return file_ids


def get_authorized_file_count(username):
    return len(_get_authorized_file_ids(username))


def get_authorized_file_counts_all_users():
    """Return authorized-file counts for every current project user."""
    results = []
    for user in User.query.order_by(User.id.asc()).all():
        count = get_authorized_file_count(user.username)
        owned_count = File.query.filter_by(owner_id=user.id).count()
        shared_count = max(0, count - owned_count)
        results.append({
            "username": user.username,
            "authorized_files": count,
            "owned_files": owned_count,
            "shared_files": shared_count,
        })
    return results


def _extract_days_from_message(text):
    """Extract 'last N days' / 'past N days' / common week wording."""
    match = re.search(
        r"\b(?:last|past|previous)\s+(\d+)\s+days?\b",
        text,
        re.IGNORECASE,
    )
    if match:
        return max(1, min(3650, int(match.group(1))))

    if re.search(r"\b(?:last|past|previous)\s+week\b", text, re.IGNORECASE):
        return 7

    if re.search(r"\b(?:last|past|previous)\s+month\b", text, re.IGNORECASE):
        return 30

    return None


def _find_subject_user(message, activity, conversation=None):
    """Resolve a named DB user; only use conversation context for pronouns."""
    lower = str(message or "").lower()

    # Explicit name always wins.
    matches = []
    for username in activity:
        if re.search(r"\b" + re.escape(str(username)) + r"\b", lower, re.IGNORECASE):
            matches.append(username)

    if matches:
        return matches[0], False

    # Follow-up pronouns may refer to the most recently named user.
    pronoun_followup = bool(re.search(
        r"\b(?:he|him|his|she|her|hers|they|them|their|that user|that person|this user)\b",
        lower,
        re.IGNORECASE,
    ))

    if pronoun_followup and isinstance(conversation, list):
        for item in reversed(conversation):
            if not isinstance(item, dict):
                continue
            content = str(item.get("content", ""))
            if str(item.get("role", "")).lower() != "user":
                continue
            content_lower = content.lower()
            for username in activity:
                if re.search(r"\b" + re.escape(str(username)) + r"\b", content_lower, re.IGNORECASE):
                    return username, True

    return None, False


def _user_summary_block(username, info):
    score = info.get("current_risk_score", 0)
    lines = [
        f"{username} is a {info.get('role', 'user')}.",
        f"Current risk: {_format_risk_score(score)} ({info.get('current_risk_level', _risk_level(score))}).",
        f"Authorized files: {info.get('authorized_file_count', 0)}",
        f"Audit/security events: {info.get('audit_event_count', 0)}",
        f"Blocked events: {info.get('blocked_event_count', 0)}",
        f"Successful events: {info.get('successful_event_count', 0)}",
        f"Login records: {info.get('login_event_count', 0)}",
        f"Failed/blocked logins: {info.get('failed_login_count', 0)}",
        f"Threat alerts: {info.get('threat_alert_count', 0)}",
        f"Historical RiskScore records: {info.get('risk_history_count', 0)}",
    ]
    return "\n".join(lines)

# ==========================================================
# USER ACTIVITY ANALYSIS
# ==========================================================

def _build_user_activity_analysis():
    """Build a complete, database-driven activity profile for every user."""
    users = User.query.order_by(User.id.asc()).all()

    audit_logs = [
        log for log in AuditLog.query.order_by(AuditLog.id.asc()).all()
        if not _is_ai_bookkeeping_log(log)
    ]
    login_history = LoginHistory.query.order_by(LoginHistory.id.asc()).all()
    threat_alerts = ThreatAlert.query.order_by(ThreatAlert.id.asc()).all()
    risk_history = _build_historical_risk_data()

    activity = {}

    for user in users:
        username = user.username

        user_logs = [
            log for log in audit_logs
            if getattr(log, "username", None) == username
        ]

        user_log_dicts = [
            _audit_record_to_dict(log)
            for log in user_logs[-500:]
        ]

        blocked = [
            item for item in user_log_dicts
            if str(item.get("status") or "").upper() == "BLOCKED"
        ]

        successful = [
            item for item in user_log_dicts
            if str(item.get("status") or "").upper() == "SUCCESS"
        ]

        user_logins = [
            login for login in login_history
            if getattr(login, "username", None) == username
        ]

        login_dicts = [
            _login_record_to_dict(login)
            for login in user_logins[-300:]
        ]

        failed_logins = [
            item for item in login_dicts
            if (
                str(item.get("status") or "").upper() in {"FAILED", "BLOCKED"}
                or "FAIL" in str(item.get("status") or "").upper()
            )
        ]

        user_alerts = [
            alert for alert in threat_alerts
            if getattr(alert, "username", None) == username
        ]

        alert_dicts = [
            _threat_record_to_dict(alert)
            for alert in user_alerts[-300:]
        ]

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for alert in alert_dicts:
            severity = str(alert.get("severity") or "").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        current_score = getattr(user, "risk_score", 0) or 0
        history = risk_history.get(username, [])
        authorized_count = get_authorized_file_count(username)

        activity[username] = {
            "username": username,
            "role": getattr(user, "role", None),
            "current_risk_score": current_score,
            "current_risk_level": _risk_level(current_score),
            "risk_history": history,
            "risk_history_count": len(history),
            "authorized_file_count": authorized_count,
            "audit_event_count": len(user_logs),
            "blocked_event_count": len(blocked),
            "successful_event_count": len(successful),
            "login_event_count": len(user_logins),
            "failed_login_count": len(failed_logins),
            "threat_alert_count": len(user_alerts),
            "threat_severity_counts": severity_counts,
            "security_events": user_log_dicts,
            "login_history": login_dicts,
            "threat_alerts": alert_dicts,
        }

    return activity

# ==========================================================
# GLOBAL SECURITY ANALYSIS
# ==========================================================

def _build_global_security_analysis():
    """Calculate project-wide risk, event, threat, and file facts."""
    users = User.query.order_by(User.id.asc()).all()
    all_logs = [
        log for log in AuditLog.query.order_by(AuditLog.id.asc()).all()
        if not _is_ai_bookkeeping_log(log)
    ]
    blocked_logs = [
        log for log in all_logs
        if str(getattr(log, "status", "") or "").upper() == "BLOCKED"
    ]
    all_alerts = ThreatAlert.query.order_by(ThreatAlert.id.asc()).all()

    risk_ranking = []
    for user in users:
        score = _safe_float(getattr(user, "risk_score", 0) or 0)
        risk_ranking.append({
            "username": user.username,
            "risk_score": score,
            "score": score,
            "risk_level": _risk_level(score),
            "level": _risk_level(score),
            "authorized_files": get_authorized_file_count(user.username),
        })
    risk_ranking.sort(key=lambda item: item["risk_score"], reverse=True)

    severity_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    risky_events = []

    for log in blocked_logs:
        action = str(getattr(log, "action", "") or "")
        upper_action = action.upper()

        if "MALWARE" in upper_action or "UNAUTHORIZED FILE ACCESS" in upper_action or "SECURE VIEWER LOCKED" in upper_action:
            severity, weight = "CRITICAL", 4
        elif upper_action in SECURITY_ACTIONS:
            severity, weight = "HIGH", 3
        elif "UNAUTHORIZED" in upper_action or "ACCESS" in upper_action or "DENIED" in upper_action or "SHARE" in upper_action:
            severity, weight = "MEDIUM", 2
        else:
            severity, weight = "LOW", 1

        risky_events.append({
            "severity": severity,
            "severity_weight": weight,
            "username": getattr(log, "username", None),
            "action": action,
            "status": getattr(log, "status", None),
            "filename": getattr(log, "filename", None),
            "timestamp": _safe_datetime_value(_record_time(log, "timestamp", "created_at", "updated_time")),
            "id": getattr(log, "id", None),
        })

    risky_events.sort(key=lambda item: (item["severity_weight"], item["id"] or 0), reverse=True)

    user_event_summary = []
    for user in users:
        username = user.username
        user_logs = [log for log in all_logs if getattr(log, "username", None) == username]
        user_event_summary.append({
            "username": username,
            "audit_events": len(user_logs),
            "blocked_events": sum(1 for log in user_logs if str(getattr(log, "status", "") or "").upper() == "BLOCKED"),
            "successful_events": sum(1 for log in user_logs if str(getattr(log, "status", "") or "").upper() == "SUCCESS"),
            "authorized_files": get_authorized_file_count(username),
        })
    user_event_summary.sort(key=lambda item: item["blocked_events"], reverse=True)

    return {
        "total_users": len(users),
        "total_files": File.query.count(),
        "total_audit_events": len(all_logs),
        "total_blocked_events": len(blocked_logs),
        "total_threat_alerts": len(all_alerts),
        "total_authorized_file_assignments": sum(get_authorized_file_count(user.username) for user in users),
        "risk_ranking": risk_ranking,
        "highest_risk_users": risk_ranking[:10],
        "user_event_summary": user_event_summary,
        "most_severe_recorded_events": risky_events[:20],
    }

# ==========================================================
# TIME WINDOW ANALYSIS
# ==========================================================

def _build_time_window_analysis(days=7):
    """Summarize actual security activity for the most recent N days."""
    now = datetime.now()
    cutoff = now - timedelta(days=days)

    recent_risks = []
    recent_audits = []
    recent_logins = []
    recent_alerts = []

    for record in RiskScore.query.order_by(RiskScore.id.asc()).all():
        dt = _parse_record_datetime(record)
        if dt and dt >= cutoff:
            recent_risks.append(_risk_record_to_dict(record))

    for record in AuditLog.query.order_by(AuditLog.id.asc()).all():
        if _is_ai_bookkeeping_log(record):
            continue
        dt = _parse_record_datetime(record)
        if dt and dt >= cutoff:
            recent_audits.append(_audit_record_to_dict(record))

    for record in LoginHistory.query.order_by(LoginHistory.id.asc()).all():
        dt = _parse_record_datetime(record)
        if dt and dt >= cutoff:
            recent_logins.append(_login_record_to_dict(record))

    for record in ThreatAlert.query.order_by(ThreatAlert.id.asc()).all():
        dt = _parse_record_datetime(record)
        if dt and dt >= cutoff:
            recent_alerts.append(_threat_record_to_dict(record))

    blocked = sum(1 for item in recent_audits if str(item.get("status") or "").upper() == "BLOCKED")
    successful = sum(1 for item in recent_audits if str(item.get("status") or "").upper() == "SUCCESS")
    failed = sum(
        1 for item in recent_logins
        if str(item.get("status") or "").upper() in {"FAILED", "BLOCKED"}
        or "FAIL" in str(item.get("status") or "").upper()
    )

    return {
        "period": f"last_{days}_days",
        "from": cutoff.isoformat(sep=" "),
        "to": now.isoformat(sep=" "),
        "risk_records": recent_risks,
        "audit_events": recent_audits[-1000:],
        "events": recent_audits[-1000:],
        "login_events": recent_logins[-500:],
        "threat_alerts": recent_alerts[-500:],
        "blocked_audit_events": blocked,
        "successful_audit_events": successful,
        "failed_login_events": failed,
        "risk_record_count": len(recent_risks),
        "audit_event_count": len(recent_audits),
        "login_event_count": len(recent_logins),
        "threat_alert_count": len(recent_alerts),
    }

# ==========================================================
# SECURITY CONTEXT
# ==========================================================

def build_security_context(user, message):
    username = user.username
    current_risk = user.risk_score or 0

    authorized_files = get_authorized_files(username)

    file_list = [
        {
            "filename": file.filename,
            "id": file.id,
            "size": getattr(file, "file_size", None),
        }
        for file in authorized_files
    ]

    activity = _build_user_activity_analysis()
    current_activity = activity.get(
        username,
        {
            "username": username,
            "role": user.role,
            "current_risk_score": current_risk,


            "current_risk_level": _risk_level(current_risk),
            "risk_history": [],
            "risk_history_count": 0,
        },
    )

    return {
        "current_user": username,
        "role": user.role,
        "risk_score": current_risk,
        "risk_level": _risk_level(current_risk),
        "authorized_files": file_list,
        "current_user_activity": current_activity,
        "all_user_activity": activity,
        "global_security_analysis": _build_global_security_analysis(),
        "authorized_file_counts": get_authorized_file_counts_all_users(),
        "last_7_days": _build_time_window_analysis(7),
    }


def get_safe_file_information(file):
    return {
        "filename": file.filename,
        "file_id": file.id,
        "file_size": getattr(file, "file_size", None),
    }

# ==========================================================
# PROJECT INFORMATION
# ==========================================================

def get_project_information():
    return {
        "project_title": (
            "AI-Powered Secure File Sharing System "
            "with Zero Trust Security and Threat Monitoring"
        ),
        "purpose": (
            "A secure file-sharing platform using encryption, Zero Trust "
            "access control, audit logging, threat detection, risk analysis "
            "and security monitoring."
        ),
        "modules": [
            "Identity and Access Management",
            "Login and Session Management",
            "Role-Based Access Control",
            "Secure File Upload",
            "File Sharing and Permissions",
            "File Encryption",
            "Integrity Protection",
            "Audit Logging",
            "Zero Trust File Access",
            "Secure File Viewer",
            "Security Violation Monitoring",
            "Threat Detection",
            "Risk Analysis",
            "Security Reports",
            "Threat Monitoring",
            "AI Security Assistant",
        ],
        "security_features": [
            "User authentication",
            "Role-based access control",
            "File permissions",
            "Encrypted file storage",
            "Zero Trust authorization",
            "Audit logging",
            "Dynamic security monitoring",
            "Copy attempt detection",
            "Save attempt detection",
            "Print attempt detection",
            "Right-click attempt detection",
            "Screenshot attempt detection",
            "Tab-switch attempt detection",
            "Secure viewer lock after repeated violations",
            "Persistent security block",
            "Risk scoring",
            "Threat monitoring",
        ],
        "technology": [
            "Python",
            "Flask",
            "SQLite",
            "SQLAlchemy",
            "Fernet encryption",
            "HTML",
            "CSS",
            "JavaScript",
            "OpenAI API",
        ],
    }

# ==========================================================
# FULL SECURITY SUMMARY
# ==========================================================

def build_full_security_summary():
    users = User.query.all()
    files = File.query.all()


    audit_logs = [
        log for log in AuditLog.query.all()
        if not _is_ai_bookkeeping_log(log)
    ]

    blocked_logs = [
        log
        for log in audit_logs
        if str(getattr(log, "status", "") or "").upper() == "BLOCKED"
    ]

    successful_logs = [
        log
        for log in audit_logs
        if str(getattr(log, "status", "") or "").upper() == "SUCCESS"
    ]

    threat_alerts = ThreatAlert.query.all()
    login_history = LoginHistory.query.all()

    user_summaries = []

    for user in users:
        username = user.username

        user_logs = [
            log
            for log in audit_logs
            if getattr(log, "username", None) == username
        ]

        user_alerts = [
            alert
            for alert in threat_alerts
            if getattr(alert, "username", None) == username
        ]

        score = user.risk_score or 0

        user_summaries.append({
            "username": username,
            "role": user.role,
            "risk_score": score,
            "risk_level": _risk_level(score),
            "blocked_events": sum(
                1
                for log in user_logs
                if str(
                    getattr(log, "status", "") or ""
                ).upper() == "BLOCKED"
            ),
            "successful_events": sum(
                1
                for log in user_logs
                if str(
                    getattr(log, "status", "") or ""
                ).upper() == "SUCCESS"
            ),
            "threat_alerts": len(user_alerts),
        })

    return {
        "total_users": len(users),
        "total_files": len(files),
        "total_audit_events": len(audit_logs),
        "blocked_events": len(blocked_logs),
        "successful_events": len(successful_logs),
        "threat_alerts": len(threat_alerts),
        "login_events": len(login_history),
        "users": user_summaries,
    }


def build_recent_security_report():
    all_logs = [
        log for log in AuditLog.query.order_by(AuditLog.id.desc()).all()
        if not _is_ai_bookkeeping_log(log)
    ][:100]

    recent_events = [
        _audit_record_to_dict(log)
        for log in all_logs
    ]

    statistics = get_threat_statistics()
    summary = build_full_security_summary()

    return {
        "security_summary": summary,
        "threat_statistics": statistics,
        "recent_events": recent_events,
    }

# ==========================================================
# AI SYSTEM PROMPT
# ==========================================================

AI_SYSTEM_PROMPT = """
You are the AI Security Assistant inside an AI-Powered Secure File Sharing


System with Zero Trust Security and Threat Monitoring.

Your job is to behave like a real conversational AI assistant for this
application, not like a fixed FAQ chatbot.

NATURAL LANGUAGE:
- Understand the user's meaning, not exact keywords.
- Handle spelling mistakes, typos, slang, abbreviations, incomplete
  sentences, casual wording, and awkward grammar.
- "whos risky", "who is most riskyy", and "who has high risk score" can
  express the same intent.
- Understand follow-up questions such as "why?", "what about David?",
  "what did he do?", "when did it happen?", "was it worse last week?",
  and "explain more".
- Use previous conversation to resolve pronouns such as he, she, they,
  that, it, this, and him.
- Do not ask the user to select from predefined questions.
- Do not claim that only certain questions are supported.
- Do not return the same canned answer just because the wording is unusual.

PROJECT-WIDE CAPABILITY:
- Every authenticated project user has the same AI analysis capabilities. Do not hard-code answers around David or any one person.
- Resolve any username that exists in the User table, including future users added to the database.
- Questions about authorized files, risk analysis, threat monitoring, security reports, audit logs, and project activity can be answered for the current user, another named user, or the whole system.
- When the user asks for "all users", "everyone", "project-wide", or gives no user name, answer from project-wide data. When they say "my", use the authenticated user.

PROJECT KNOWLEDGE:
- Answer questions about the whole project: architecture, purpose,
  modules, security features, technologies, Zero Trust, encryption,
  authentication, permissions, audit logging, secure viewing, threat
  monitoring, risk analysis, reports, and the AI assistant.
- If the question concerns live project data, use the supplied database
  context rather than guessing.
- You may analyze users, risk scores, historical RiskScore records, audit
  activity, login history, threat alerts, blocked events, security
  violations, and threat patterns.
- If asked about a named user, analyze THAT named user. Do not silently
  substitute the authenticated user.
- "my" or "me" means the authenticated user.
- If asked about another project user, use the supplied security metadata.
- Never invent an event, timestamp, score, activity, or reason that is not
  present in the supplied context.

RISK ANALYSIS:
- RiskScore history contains historical records. Use the entire supplied
  history when answering trend questions.
- Do not assume the latest score is the whole history.
- For questions such as "past week", "last 7 days", "previous activity",
  "when did the score rise", "what caused the spike", or "what was theriskiest event", compare the relevant historical records and security
  events.
- Explain risk using evidence from audit events, login activity, threat
  alerts, security violations, unauthorized access, and recorded scores.
- Distinguish between a stored current risk score and historical risk
  records.
- If the data does not establish causation, say "the records suggest" or
  "the available data does not prove the cause" instead of pretending to
  know.
- When identifying the most serious event, use actual recorded severity
  and security-event information.

FILES AND ZERO TRUST:
- The assistant can discuss the file-sharing functionality and authorized
  file metadata.
- Never disclose protected file contents through the AI.
- Never provide unauthorized or private file contents.
- Never reveal passwords, API keys, encryption keys, Flask secret keys,
  database credentials, access tokens, or other secrets.
- Never help bypass authentication, authorization, Zero Trust controls,
  monitoring, audit logging, viewer locks, or other security controls.
- Never help delete, hide, alter, or evade security evidence.

GENERAL QUESTIONS:
- If the user asks a normal general question that is unrelated to the
  project, answer normally when safe.
- Do not force every answer to mention SecureVault.
- Keep explanations clear and human-like. Use technical detail when useful.
"""

# ==========================================================
# AI SAFETY VALIDATION
# ==========================================================

def validate_ai_response(answer):
    if not answer:
        return "I could not generate a response."

    forbidden_patterns = [
        r"\bapi[\s_-]*key\s*[:=]",
        r"\bsecret[\s_-]*key\s*[:=]",
        r"\bencryption[\s_-]*key\s*[:=]",
        r"\bflask[\s_-]*secret\s*[:=]",
        r"\bdatabase[\s_-]*password\s*[:=]",
        r"\baccess[\s_-]*token\s*[:=]",
    ]

    for pattern in forbidden_patterns:
        if re.search(pattern, answer, re.IGNORECASE):
            return (
                "SENSITIVE INFORMATION BLOCKED\n\n"
                "I cannot provide system credentials, passwords, API keys, "
                "encryption keys, tokens, secret keys or other protected "
                "information."
            )


    return answer

# ==========================================================
# AI QUESTION SAFETY FILTER
# ==========================================================

def detect_inappropriate_question(message):
    """Block direct secret-exfiltration, bypass, and evidence-removal requests."""
    text = re.sub(
        r"\s+",
        " ",
        str(message or "").lower().strip(),
    )

    credential_request_patterns = [
        r"\b(?:what|whats|what's|tell|show|give|reveal|display|provide|find|get|retrieve|recover|list)\b.{0,80}\b(?:another|other|someone(?:\s+else)?s?|user|users|david|alice|bob|charlie)\b.{0,50}\bpassword\b",
        r"\bpassword\b.{0,50}\b(?:another|other|someone(?:\s+else)?s?|user|users)\b",
        r"\b(?:another|other|someone(?:\s+else)?s?|user|users)\b.{0,50}\b(?:password|passwd|credential|credentials|token|api key|secret key|private key)\b",
        r"\b(?:show|give|tell|reveal|display|provide|find|get|retrieve|recover)\b.{0,80}\b(?:api key|secret key|encryption key|private key|access token|database password|flask secret)\b",
    ]

    if any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in credential_request_patterns
    ):
        return {
            "type": "credential",
            "title": "SECURITY WARNING",
            "message": (
                "I can't provide or retrieve another user's password, "
                "credentials, API keys, encryption keys, tokens or other "
                "protected secrets."
            ),
        }

    secret_value_patterns = [
        r"\b(?:show|give|tell|reveal|display|provide|retrieve|recover)\b.{0,60}\bmy\b.{0,40}\b(?:password|api key|secret key|encryption key|token)\b",
        r"\b(?:show|give|tell|reveal|display|provide)\b.{0,60}\b(?:password|api key|secret key|encryption key|private key|token)\b",
    ]

    if any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in secret_value_patterns
    ):
        return {
            "type": "credential",
            "title": "SENSITIVE INFORMATION BLOCKED",
            "message": (
                "I can't disclose passwords, API keys, encryption keys, "
                "tokens, secret keys or other protected credentials."
            ),
        }

    bypass_patterns = [
        r"\bbypass\b",
        r"\bcircumvent\b",
        r"\bget around\b",
        r"\bbreak into\b",
        r"\bhack into\b",
        r"\bdisable (?:security|zero trust|monitoring|audit logging)\b",
        r"\bavoid (?:detection|monitoring|audit logging)\b",
        r"\bevad(?:e|ing) (?:detection|monitoring)\b",
    ]

    if any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in bypass_patterns
    ):
        return {
            "type": "bypass",
            "title": "SECURITY WARNING",
            "message": (
                "I can't provide instructions for bypassing authentication, "
                "authorization, Zero Trust controls, monitoring, audit logging "
                "or other security protections."
            ),
        }

    evidence_patterns = [
        r"\b(?:delete|remove|erase|hide|alter|clear)\b.{0,50}\b(?:audit logs?|security evidence|violations?)\b"
    ]

    if any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in evidence_patterns
    ):
        return {
            "type": "evidence",
            "title": "SECURITY ACTION BLOCKED",
            "message": (
                "I can't provide instructions for deleting, hiding, altering "
                "or removing security audit records, violations or evidence."
            ),


        }

    unauthorized_file_patterns = [
        r"\b(?:show|read|open|give|access)\b.{0,60}\b(?:someone else'?s|anotheruser'?s|private|unauthorized|confidential)\b.{0,60}\bfile\b",
        r"\bdecrypt\b.{0,80}\b(?:someone else|unauthorized|private|protected)\b",
    ]

    if any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in unauthorized_file_patterns
    ):
        return {
            "type": "file",
            "title": "ACCESS RESTRICTED",
            "message": (
                "The requested file may be protected by Zero Trust access "
                "control. I can't provide protected or unauthorized file contents."
            ),
        }

    return None

# ==========================================================
# LOCAL FALLBACK
# ==========================================================

def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _format_risk_score(value):
    number = _safe_float(value)
    return str(int(number)) if number.is_integer() else f"{number:.1f}"


def _local_project_ai_fallback(message, security_context, requested_file=None):
    """
    Project-wide, user-wide natural-language fallback.

    This handler is deliberately database-driven. It is not limited to one
    person and it does not depend on a fixed list of exact questions.
    """
    text = re.sub(r"\s+", " ", str(message or "").strip())
    lower = text.lower()

    if not text:
        return "Tell me what you want to know about the project, users, risks, threats, files, reports, or security activity."

    activity = security_context.get("all_user_activity", {}) or {}
    global_data = security_context.get("global_security_analysis", {}) or {}
    current_user = security_context.get("current_user") or "User"
    current_activity = security_context.get("current_user_activity", {}) or {}
    conversation = session.get("ai_conversation", [])

    named_user, from_followup = _find_subject_user(text, activity, conversation)
    selected = activity.get(named_user, current_activity) if named_user else current_activity

    # ------------------------------------------------------------------
    # CASUAL CHAT
    # ------------------------------------------------------------------
    if re.fullmatch(
        r"(?:hi|hey|hello|heyy+|hii+|yo|good morning|good afternoon|good evening)[!. ]*",
        lower,
    ):
        return f"Hey {current_user}! 👋 What would you like to know about the security system?"

    if re.fullmatch(r"(?:thanks|thank you|thx|ty)[!. ]*", lower):
        return "You're welcome! 😊"

    # ------------------------------------------------------------------
    # IDENTITY
    # ------------------------------------------------------------------
    if re.search(
        r"\b(who am i|who i am|what(?:'s| is) my name|my username|which user am i|what user am i)\b",
        lower,
    ):
        score = current_activity.get("current_risk_score", security_context.get("risk_score", 0))
        return (
            f"You are {current_user}.\n"
            f"Role: {current_activity.get('role', security_context.get('role', 'user'))}.\n"
            f"Current risk: {_format_risk_score(score)} ({_risk_level(score)}).\n"
            f"Authorized files: {current_activity.get('authorized_file_count', 0)}."
        )

    # ------------------------------------------------------------------
    # DAYS / TIME WINDOWS -- SUPPORT ANY N DAYS
    # ------------------------------------------------------------------
    days = _extract_days_from_message(lower)
    asks_all_users = bool(
        re.search(
            r"\b(all users|every user|everyone|all user|overall|project[- ]wide|across the system|whole system)\b",
            lower,
        )
    )
    asks_time = bool(days is not None)

    if asks_time:
        window = _build_time_window_analysis(days)
        label = f"the last {days} day" + ("s" if days != 1 else "")
        audits = window.get("audit_events", []) or []
        risks = window.get("risk_records", []) or []
        logins = window.get("login_events", []) or []
        alerts = window.get("threat_alerts", []) or []

        if named_user and not asks_all_users:
            user_events = [
                e for e in audits
                if str(e.get("username", "")).lower() == str(named_user).lower()
            ]
            user_risks = [
                r for r in risks
                if str(r.get("username", "")).lower() == str(named_user).lower()
            ]
            user_alerts = [
                a for a in alerts
                if str(a.get("username", "")).lower() == str(named_user).lower()
            ]

            lines = [f"Security activity for {named_user} during {label}:"]
            lines.append(f"- Security events: {len(user_events)}")
            lines.append(
                f"- Blocked events: {sum(1 for e in user_events if str(e.get('status', '')).upper() == 'BLOCKED')}"
            )
            lines.append(f"- Login events: {len([x for x in logins if str(x.get('username','')).lower() == str(named_user).lower()])}")
            lines.append(f"- Threat alerts: {len(user_alerts)}")

            if user_risks:
                vals = [_safe_float(x.get("risk_score", x.get("score", 0))) for x in user_risks]
                lines.append(
                    f"- Risk score range: {_format_risk_score(min(vals))} to {_format_risk_score(max(vals))}"
                )

            if user_events:
                lines.append("\nRecorded events:")
                for e in reversed(user_events[-15:]):
                    lines.append(
                        f"- {e.get('timestamp', 'time unavailable')}: "
                        f"{e.get('action', 'Unknown event')} "
                        f"({e.get('status', 'UNKNOWN')})"
                    )
            else:
                lines.append("- No audit events were recorded for this user in that period.")

            return "\n".join(lines)

        # Project-wide time-window answer. Do NOT make it user-specific.
        lines = [f"Security activity across all users for {label}:"]
        lines.append(f"- Security/audit events: {len(audits)}")
        lines.append(f"- Blocked security events: {window.get('blocked_audit_events', 0)}")
        lines.append(f"- Successful security events: {window.get('successful_audit_events', 0)}")
        lines.append(f"- Login events: {len(logins)}")
        lines.append(f"- Failed/blocked logins: {window.get('failed_login_events', 0)}")
        lines.append(f"- Threat alerts: {len(alerts)}")
        lines.append(f"- Historical RiskScore records: {len(risks)}")

        if risks:
            vals = [_safe_float(x.get("risk_score", x.get("score", 0))) for x in risks]
            lines.append(
                f"- Risk score range in those records: {_format_risk_score(min(vals))} to {_format_risk_score(max(vals))}"
            )

        if audits:
            lines.append("\nRecent recorded events:")
            for e in reversed(audits[-15:]):
                lines.append(
                    f"- {e.get('timestamp', 'time unavailable')}: "
                    f"{e.get('username', 'Unknown user')} - "
                    f"{e.get('action', 'Unknown event')} "
                    f"({e.get('status', 'UNKNOWN')})"
                )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # AUTHORIZED FILES -- CURRENT USER, NAMED USER, OR ALL USERS
    # ------------------------------------------------------------------
    asks_authorized_files = bool(
        re.search(
            r"\b(authorized files?|authorised files?|authorized file count|authorised file count|"
            r"how many (files?|documents?).*(authorized|authorised|access)|"
            r"how many files.*can .* access|what files.*can .* access|"
            r"files? .*allowed to (access|view))\b",
            lower,
        )
    )

    if asks_authorized_files:
        counts = security_context.get("authorized_file_counts", []) or get_authorized_file_counts_all_users()

        if named_user and not asks_all_users:
            info = activity.get(named_user, {})
            return (
                f"{named_user} has access to "
                f"{info.get('authorized_file_count', get_authorized_file_count(named_user))} authorized file(s)."
            )

        if re.search(r"\b(my|mine|i|me|my files)\b", lower) and not asks_all_users:
            return (
                f"You ({current_user}) have access to "
                f"{current_activity.get('authorized_file_count', get_authorized_file_count(current_user))} authorized file(s)."
            )

        lines = ["Authorized files by user:"]
        for item in counts:
            lines.append(
                f"- {item['username']}: {item['authorized_files']} authorized file(s) "
                f"({item['owned_files']} owned, {item['shared_files']} shared)"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # RISK ANALYSIS / RISK SCORE CALCULATION
    # ------------------------------------------------------------------
    if re.search(
        r"\b(risk analysis|risk score calculation|how (does|is) the risk score|"
        r"calculate risk|risk engine|risk assessment|risk level|risk methodology|"
        r"how is risk calculated|how do you calculate risk)\b",
        lower,
    ):
        ranking = global_data.get("risk_ranking", []) or []
        lines = [
            "Risk Analysis evaluates each user's recorded security activity and assigns a current risk score.",
            "The score is based on critical/high/medium/low threat alerts, unauthorized access, security violations, failed logins, new-device activity, and suspicious activity.",
            "Category contributions are capped so repeated events do not automatically force every user to the maximum.",
            f"The final calculated score is capped at MAX_RISK_SCORE = {MAX_RISK_SCORE}.",
            "Risk levels: LOW < 30, MEDIUM 30-59, HIGH 60-79, CRITICAL 80+.",
        ]
        if named_user:
            info = activity.get(named_user, selected)
            lines.append(
                f"\n{named_user}: current score {_format_risk_score(info.get('current_risk_score', 0))} ({info.get('current_risk_level', 'LOW')})."
            )
            history = info.get("risk_history", []) or []
            if history:
                vals = [_safe_float(x.get("risk_score", x.get("score", 0))) for x in history]
                lines.append(
                    f"Historical range: {_format_risk_score(min(vals))} to {_format_risk_score(max(vals))} across {len(vals)} RiskScore record(s)."
                )
        else:
            lines.append("\nCurrent project-wide risk ranking:")
            for i, item in enumerate(ranking[:10], 1):
                score = item.get("risk_score", item.get("score", 0))
                level = item.get("risk_level", item.get("level", _risk_level(score)))
                lines.append(f"{i}. {item.get('username')} - {_format_risk_score(score)} ({level})")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # RISK TREND / PREVIOUS SCORE QUESTIONS
    # ------------------------------------------------------------------
    if re.search(
        r"\b(risk.*(increase|decrease|change|rise|fall|spike|trend)|"
        r"(increase|decrease|change|rise|fall|spike|trend).*risk|"
        r"previous risk scores?|past risk scores?|historical risk|risk history|"
        r"score over time)\b",
        lower,
    ):
        if named_user:
            history = selected.get("risk_history", []) or []
            if not history:
                return f"No historical RiskScore records are available for {named_user}."

            vals = []
            for item in history:
                vals.append((
                    item.get("updated_time"),
                    _safe_float(item.get("risk_score", item.get("score", 0)))
                ))

            lines = [f"{named_user}'s historical risk records:"]
            for stamp, score in vals[-15:]:
                lines.append(f"- {stamp or 'time unavailable'}: {_format_risk_score(score)} ({_risk_level(score)})")

            if len(vals) >= 2:
                previous = vals[-2][1]
                latest = vals[-1][1]
                diff = latest - previous
                direction = "increased" if diff > 0 else "decreased" if diff < 0 else "did not change"
                lines.append(
                    f"\nThe latest stored score {direction}: "
                    f"{_format_risk_score(previous)} → {_format_risk_score(latest)} "
                    f"({diff:+.0f})."
                )
            return "\n".join(lines)

        # Global historical risk summary.
        lines = ["Project-wide historical risk view:"]
        for username, info in activity.items():
            history = info.get("risk_history", []) or []
            if history:
                vals = [_safe_float(x.get("risk_score", x.get("score", 0))) for x in history]
                lines.append(
                    f"- {username}: {_format_risk_score(vals[0])} → {_format_risk_score(vals[-1])} "
                    f"(range {_format_risk_score(min(vals))}-{_format_risk_score(max(vals))}, {len(vals)} record(s))"
                )
        return "\n".join(lines) if len(lines) > 1 else "No historical RiskScore records are available."

    # ------------------------------------------------------------------
    # THREAT MONITORING / RECENT THREATS
    # ------------------------------------------------------------------
    asks_recent_threat = bool(
        re.search(r"\b(most recent threat|latest threat|recent threat|newest threat|recent attack|latest attack)\b", lower)
    )

    asks_threat = bool(
        re.search(
            r"\b(threat monitoring|threat monitor|threat status|threat picture|"
            r"security threats?|threat activity|threats?|attacks?|alerts?|"
            r"security incidents?|incidents?|malware)\b",
            lower,
        )
    )

    if asks_threat:
        stats = get_threat_statistics()
        alert_records = [
            _threat_record_to_dict(a)
            for a in ThreatAlert.query.order_by(ThreatAlert.id.desc()).limit(20).all()
        ]

        lines = [
            "Threat Monitoring provides a project-wide view of detected threats and security activity.",
            f"- Critical threats: {stats.get('critical_threats', 0)}",
            f"- High threats: {stats.get('high_threats', 0)}",
            f"- Medium threats: {stats.get('medium_threats', 0)}",
            f"- Low threats: {stats.get('low_threats', 0)}",
            f"- Threat alerts: {stats.get('security_alerts', 0)}",
            f"- Unauthorized-access events: {stats.get('unauthorized_access', 0)}",
            f"- Suspicious/security-violation events: {stats.get('suspicious_behaviour', 0)}",
            f"- Malware-related events: {stats.get('malware_threats', 0)}",
        ]

        if asks_recent_threat:
            if named_user:
                alert_records = [x for x in alert_records if str(x.get('username','')).lower() == str(named_user).lower()]
            if alert_records:
                latest = alert_records[0]
                lines.append(
                    f"\nMost recent recorded ThreatAlert: {latest.get('timestamp', 'time unavailable')} - "
                    f"{latest.get('username', 'Unknown user')} - "
                    f"{latest.get('severity', 'UNKNOWN')} - "
                    f"{latest.get('type') or latest.get('description') or 'Threat alert'}"
                )
            else:
                # Fall back to real blocked security events when ThreatAlert table is empty.
                events = global_data.get("most_severe_recorded_events", []) or []
                if named_user:
                    events = [e for e in events if str(e.get('username','')).lower() == str(named_user).lower()]
                if events:
                    e = events[0]
                    lines.append(
                        f"\nNo ThreatAlert record is stored, but the most recent high-priority recorded security event is "
                        f"{e.get('timestamp', 'time unavailable')} - {e.get('username', 'Unknown user')} - {e.get('action', 'Unknown event')} ({e.get('severity', 'UNKNOWN')})."
                    )
                else:
                    lines.append("\nNo threat or high-priority security event is currently recorded.")
        else:
            if alert_records:
                lines.append("\nRecent threat alerts:")
                for item in alert_records[:10]:
                    lines.append(
                        f"- {item.get('timestamp','time unavailable')}: {item.get('username','Unknown user')} - "
                        f"{item.get('severity','UNKNOWN')} - {item.get('type') or item.get('description') or 'Threat alert'}"
                    )
            else:
                lines.append("\nNo ThreatAlert records are currently stored in the database.")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # MOST SERIOUS / RISKIEST EVENT
    # ------------------------------------------------------------------
    if re.search(
        r"\b(most risky event|riskiest event|most serious event|worst security event|"
        r"most dangerous event|biggest security event|biggest threat event|"
        r"most serious incident|worst incident|most dangerous incident)\b",
        lower,
    ):
        events = global_data.get("most_severe_recorded_events", []) or []
        if named_user:
            events = [e for e in events if str(e.get("username", "")).lower() == str(named_user).lower()]

        if not events:
            return f"I don't have a recorded high-severity event{' for ' + named_user if named_user else ''}."

        e = events[0]
        answer = (
            f"The most serious recorded event"
            f"{' for ' + named_user if named_user else ''}"
            f" was '{e.get('action', 'Unknown event')}' involving {e.get('username', 'Unknown user')}."
        )
        if e.get("severity"):
            answer += f" Severity: {e['severity']}."
        if e.get("timestamp"):
            answer += f" Recorded at {e['timestamp']}."
        if e.get("filename") and e.get("filename") != "Secure Viewer":
            answer += f" File: {e['filename']}."
        return answer

    # ------------------------------------------------------------------
    # USER COMPARISON
    # ------------------------------------------------------------------
    named_users = [
        u for u in activity
        if re.search(r"\b" + re.escape(str(u)) + r"\b", lower, re.IGNORECASE)
    ]

    if len(named_users) >= 2 and re.search(r"\b(compare|versus|vs\.?|difference|between)\b", lower):
        rows = ["User comparison based on current database values:"]
        for username in named_users:
            info = activity[username]
            rows.append(
                f"- {username}: risk {_format_risk_score(info.get('current_risk_score', 0))} "
                f"({info.get('current_risk_level', 'LOW')}), "
                f"blocked {info.get('blocked_event_count', 0)}, "
                f"threat alerts {info.get('threat_alert_count', 0)}, "
                f"authorized files {info.get('authorized_file_count', 0)}"
            )
        return "\n".join(rows)

    # ------------------------------------------------------------------
    # RISK RANKING / SAFEST / MOST RISKY USER
    # ------------------------------------------------------------------
    asks_safest = bool(re.search(r"\b(safest user|lowest risk|least risky|most safe|safest)\b", lower))
    asks_highest = bool(re.search(r"\b(highest risk|highest score|high risk|most risky user|riskiest user|who is risky|who has high risk)\b", lower))

    if (asks_safest or asks_highest) and not named_user:
        ranking = global_data.get("risk_ranking", []) or []
        if not ranking:
            return "No current user risk records are available."

        if asks_safest:
            item = min(ranking, key=lambda x: _safe_float(x.get("risk_score", x.get("score", 0))))
            return (
                f"The safest user by current recorded risk is {item.get('username')} "
                f"with a score of {_format_risk_score(item.get('risk_score', item.get('score', 0)))} "
                f"({item.get('risk_level', item.get('level', 'LOW'))})."
            )

        high = [
            item for item in ranking
            if _safe_float(item.get("risk_score", item.get("score", 0))) >= 60
        ]
        lines = ["Current risk ranking:"]
        for i, item in enumerate(ranking[:10], 1):
            score = item.get("risk_score", item.get("score", 0))
            lines.append(
                f"{i}. {item.get('username')} - {_format_risk_score(score)} "
                f"({item.get('risk_level', item.get('level', 'LOW'))})"
            )
        lines.append(
            "HIGH/CRITICAL users: "
            + (", ".join(x.get("username", "Unknown") for x in high) if high else "none")
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # BLOCKED / SCREENSHOT / COPY / SAVE / PRINT / TAB EVENTS
    # ------------------------------------------------------------------
    if re.search(
        r"\b(screenshot|screen shot|tab switch|tab-switch|copy attempt|save attempt|"
        r"print attempt|right click|blocked attempts?|security violations?|"
        r"unauthorized access|suspicious activity|blocked events?)\b",
        lower,
    ):
        logs = [
            log for log in AuditLog.query.all()
            if not _is_ai_bookkeeping_log(log)
        ]

        target_user = named_user

        def user_ok(log):
            return not target_user or str(getattr(log, "username", "")).lower() == str(target_user).lower()

        phrase_to_action = {
            "screenshot": "SCREENSHOT_ATTEMPT",
            "screen shot": "SCREENSHOT_ATTEMPT",
            "tab switch": "TAB_SWITCH_ATTEMPT",
            "tab-switch": "TAB_SWITCH_ATTEMPT",
            "copy attempt": "COPY_ATTEMPT",
            "save attempt": "SAVE_ATTEMPT",
            "print attempt": "PRINT_ATTEMPT",
            "right click": "RIGHT_CLICK_ATTEMPT",
        }

        for phrase, action in phrase_to_action.items():
            if phrase in lower:
                count = sum(
                    1 for log in logs
                    if user_ok(log)
                    and str(getattr(log, "action", "") or "").upper() == action
                )
                return (
                    f"There were {count} {action.replace('_', ' ').lower()}(s)"
                    f"{' for ' + named_user if named_user else ' across all users'}."
                )

        if "unauthorized" in lower:
            matches = [
                log for log in logs
                if user_ok(log)
                and (
                    "UNAUTHORIZED" in str(getattr(log, "action", "") or "").upper()
                    or "ACCESS DENIED" in str(getattr(log, "action", "") or "").upper()
                )
            ]
            return (
                f"There were {len(matches)} recorded unauthorized-access/denial event(s)"
                f"{' for ' + named_user if named_user else ' across the system'}."
            )

        if "suspicious" in lower:
            matches = [
                log for log in logs
                if user_ok(log)
                and (
                    str(getattr(log, "action", "") or "").upper() in SECURITY_ACTIONS
                    or any(
                        word in str(getattr(log, "action", "") or "").upper()
                        for word in ("SUSPICIOUS", "ATTACK", "MALWARE", "THREAT")
                    )
                )
            ]
            return (
                f"I found {len(matches)} suspicious/security-violation event(s)"
                f"{' for ' + named_user if named_user else ' across the system'}."
            )

        blocked = [
            log for log in logs
            if user_ok(log)
            and str(getattr(log, "status", "") or "").upper() == "BLOCKED"
        ]
        return (
            f"There were {len(blocked)} blocked security event(s)"
            f"{' for ' + named_user if named_user else ' across the system'}."
        )

    # ------------------------------------------------------------------
    # AUDIT LOGS
    # ------------------------------------------------------------------
    if re.search(
        r"\b(audit logs?|audit log summary|summari[sz]e.*audit|security logs?|audit activity|recent audit events?)\b",
        lower,
    ):
        logs = [
            log for log in AuditLog.query.order_by(AuditLog.id.desc()).all()
            if not _is_ai_bookkeeping_log(log)
        ]
        if named_user:
            logs = [log for log in logs if getattr(log, "username", None) == named_user]

        blocked = sum(1 for log in logs if str(getattr(log, "status", "") or "").upper() == "BLOCKED")
        successful = sum(1 for log in logs if str(getattr(log, "status", "") or "").upper() == "SUCCESS")

        lines = [
            f"Audit Log summary{' for ' + named_user if named_user else ' across the system'}:",
            f"- Total audit events: {len(logs)}",
            f"- Blocked events: {blocked}",
            f"- Successful events: {successful}",
        ]

        if logs:
            lines.append("\nMost recent audit events:")
            for log in logs[:15]:
                item = _audit_record_to_dict(log)
                lines.append(
                    f"- {item.get('timestamp', 'time unavailable')}: "
                    f"{item.get('username', 'Unknown user')} - "
                    f"{item.get('action', 'Unknown event')} "
                    f"({item.get('status', 'UNKNOWN')})"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # SECURITY REPORTS
    # ------------------------------------------------------------------
    if re.search(
        r"\b(security reports?|security report|reporting|report page|"
        r"what is in the report|summari[sz]e.*report|report data|security report data)\b",
        lower,
    ):
        summary = build_full_security_summary()
        stats = get_threat_statistics()
        lines = [
            "Security Reports provide a consolidated view of the project's security state using live database data.",
            f"- Users: {summary.get('total_users', 0)}",
            f"- Files: {summary.get('total_files', 0)}",
            f"- Security audit events: {summary.get('total_audit_events', 0)}",
            f"- Blocked security events: {summary.get('blocked_events', 0)}",
            f"- Successful security events: {summary.get('successful_events', 0)}",
            f"- Login events: {summary.get('login_events', 0)}",
            f"- Threat alerts: {summary.get('threat_alerts', 0)}",
            f"- Critical threats: {stats.get('critical_threats', 0)}",
            f"- High threats: {stats.get('high_threats', 0)}",
            f"- Unauthorized-access events: {stats.get('unauthorized_access', 0)}",
            "\nReports can be used to review risk, audit activity, blocked actions, login history, threats, files, and overall security status.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # PROJECT / MODULES / FEATURES
    # ------------------------------------------------------------------
    if re.search(
        r"\b(project|system|application|app|all modules|modules|features|"
        r"technology|technologies|tech stack|explain my project|what is this project|"
        r"what does this project do|architecture|security features)\b",
        lower,
    ):
        info = get_project_information()
        return (
            f"{info['project_title']}\n\n"
            f"Purpose: {info['purpose']}\n\n"
            "Modules:\n- " + "\n- ".join(info["modules"]) + "\n\n"
            "Security features:\n- " + "\n- ".join(info["security_features"]) + "\n\n"
            "Technology stack: " + ", ".join(info["technology"])
        )

    # ------------------------------------------------------------------
    # ENCRYPTION / ZERO TRUST
    # ------------------------------------------------------------------
    if re.search(r"\b(encryption|encrypt|fernet|aes|how does encryption work|how are files protected|file protection)\b", lower):
        return (
            "The project protects files through multiple layers. Files are stored in encrypted form, while authentication, role-based permissions, and Zero Trust file-access checks determine who may access them. "
            "Audit logging records important security activity, and the secure viewer monitors actions such as copy, save, print, right-click, screenshot, and tab switching. "
            "The project information records Fernet encryption in the technology stack."
        )

    if re.search(r"\b(zero trust|zero-trust|how does zero trust work|how does zero trust work here)\b", lower):
        return (
            "Zero Trust means the system does not automatically trust a user just because they are logged in. For a protected file request, the application checks the authenticated identity, verifies ownership or an explicit file permission, and blocks unauthorized access. "
            "Blocked requests are recorded as security events so they can contribute to monitoring and risk analysis."
        )

    # ------------------------------------------------------------------
    # USER PROFILE / ACTIVITY
    # ------------------------------------------------------------------
    if named_user and (
        re.search(
            r"\b(tell me about|what about|who is|profile|details|information|"
            r"previous activity|activity|activities|what did|what has|did .* do|"
            r"history|logs|behavior|behaviour|security status)\b",
            lower,
        )
        or from_followup
    ):
        events = selected.get("security_events", []) or []
        history = selected.get("risk_history", []) or []

        if re.search(r"\b(activity|activities|what did|previous|history|logs|what has|behavior|behaviour)\b", lower) or from_followup:
            lines = [f"Here’s the recorded activity for {named_user}:"]
            lines.append(f"- Role: {selected.get('role', 'user')}")
            lines.append(f"- Current risk: {_format_risk_score(selected.get('current_risk_score', 0))} ({selected.get('current_risk_level', 'LOW')})")
            lines.append(f"- Authorized files: {selected.get('authorized_file_count', 0)}")
            lines.append(f"- Audit/security events: {len(events)}")
            lines.append(f"- Blocked events: {selected.get('blocked_event_count', 0)}")
            lines.append(f"- Successful events: {selected.get('successful_event_count', 0)}")
            lines.append(f"- Login records: {selected.get('login_event_count', 0)}")
            lines.append(f"- Failed/blocked logins: {selected.get('failed_login_count', 0)}")
            lines.append(f"- Threat alerts: {selected.get('threat_alert_count', 0)}")

            if history:
                vals = [_safe_float(x.get('risk_score', x.get('score', 0))) for x in history]
                lines.append(
                    f"- Historical RiskScore records: {len(history)} "
                    f"(range {_format_risk_score(min(vals))} to {_format_risk_score(max(vals))})"
                )

            if events:
                lines.append("\nRecent recorded events:")
                for e in reversed(events[-15:]):
                    lines.append(
                        f"- {e.get('timestamp', 'time unavailable')}: "
                        f"{e.get('action', 'Unknown event')} "
                        f"({e.get('status', 'UNKNOWN')})"
                    )
            return "\n".join(lines)

        return _user_summary_block(named_user, selected)

    # ------------------------------------------------------------------
    # REQUESTED AUTHORIZED FILE METADATA
    # ------------------------------------------------------------------
    if requested_file:
        safe = get_safe_file_information(requested_file)
        return (
            f"The authorized file is '{safe['filename']}'. "
            f"File ID: {safe['file_id']}. Recorded size: {safe['file_size']}."
        )

    # ------------------------------------------------------------------
    # GENERIC BUT USEFUL PROJECT-WIDE ANSWER
    # ------------------------------------------------------------------
    summary = build_full_security_summary()
    return (
        f"I can analyze the entire project, not just one user. The current database contains "
        f"{summary.get('total_users', 0)} users, {summary.get('total_files', 0)} files, "
        f"{summary.get('total_audit_events', 0)} security audit events and "
        f"{summary.get('threat_alerts', 0)} threat alerts. "
        "I can answer about risk analysis, threat monitoring, security reports, audit logs, "
        "authorized files, any project user, historical activity, or specific time periods."
    )

def _summarize_time_window(window, label):
    if not isinstance(window, dict):
        return f"I don't have enough recorded data to summarize {label}."

    audit_events = window.get("audit_events", []) or []
    risk_records = window.get("risk_records", []) or []
    login_events = window.get("login_events", []) or []
    threat_alerts = window.get("threat_alerts", []) or []

    lines = [
        f"Security activity for {label}:"
    ]

    lines.append(f"- Audit/security events: {len(audit_events)}")
    lines.append(
        f"- Blocked audit events: {window.get('blocked_audit_events', 0)}"
    )
    lines.append(
        f"- Successful audit events: {window.get('successful_audit_events', 0)}"
    )
    lines.append(f"- Login events: {len(login_events)}")
    lines.append(
        f"- Failed/blocked logins: {window.get('failed_login_events', 0)}"
    )
    lines.append(f"- Threat alerts: {len(threat_alerts)}")
    lines.append(f"- Historical risk records: {len(risk_records)}")

    if risk_records:
        scores = []

        for item in risk_records:
            value = item.get(
                "risk_score",
                item.get("score"),
            )
            try:
                scores.append(float(value))
            except Exception:
                pass

        if scores:
            lines.append(
                "- Risk score range: "
                f"{_format_risk_score(min(scores))} to "
                f"{_format_risk_score(max(scores))}"
            )

    if audit_events:
        lines.append("\nRecorded security events:")

        for event in reversed(audit_events[-10:]):
            lines.append(
                f"- {event.get('timestamp', 'time unavailable')}: "
                f"{event.get('username', 'Unknown user')} - "
                f"{event.get('action', 'Unknown event')} "
                f"({event.get('status', 'UNKNOWN')})"
            )

    if not audit_events and not risk_records:
        return f"No timestamped security records were found for {label}."
    return "\n".join(lines)


# ==========================================================
# OPENAI RESPONSE EXTRACTION
# ==========================================================

def _extract_openai_text(response):
    """Support Responses API and Chat Completions response shapes."""
    text = getattr(response, "output_text", None)

    if text:
        return str(text).strip()

    choices = getattr(response, "choices", None)

    if choices:
        try:
            content = choices[0].message.content
            if content:
                return str(content).strip()
        except Exception:
            pass

    return ""

# ==========================================================
# OPENAI CLIENT
# ==========================================================

def get_openai_client():
    if OpenAI is None:
        print("AI ERROR: OpenAI package is not installed.")
        return None

    if not OPENAI_API_KEY:
        print("AI ERROR: OPENAI_API_KEY was not loaded.")
        return None

    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        print("AI: OpenAI client initialized successfully.")
        return client
    except Exception as e:
        print("AI CLIENT INITIALIZATION ERROR:", repr(e))
        return None

# ==========================================================
# AI CONTEXT
# ==========================================================

def _build_ai_context(
    user,
    message,
    security_context,
    requested_file=None,
):
    project_information = get_project_information()
    security_summary = build_full_security_summary()
    recent_security_report = build_recent_security_report()

    safe_context = {
        "authenticated_user": {
            "username": user.username,
            "role": user.role,
        },
        "project_information": project_information,
        "project_security_summary": security_summary,
        "security_context": security_context,
        "recent_security_report": recent_security_report,
        "requested_authorized_file": None,
    }

    if requested_file:
        safe_context["requested_authorized_file"] = (
            get_safe_file_information(requested_file)
        )

    return safe_context


def _append_ai_conversation(message, answer):
    """Persist a bounded conversation window for follow-up questions."""
    conversation = session.get("ai_conversation", [])

    if not isinstance(conversation, list):
        conversation = []

    conversation = conversation[-10:]
    conversation.append({
        "role": "user",
        "content": str(message)[:4000],
    })
    conversation.append({
        "role": "assistant",
        "content": str(answer)[:4000],
    })

    session["ai_conversation"] = conversation[-10:]
    session.modified = True
# ==========================================================


# AI ANSWER GENERATION
# ==========================================================

def generate_ai_answer(message, security_context, requested_file=None):
    """Generate a natural AI answer, with a project-aware DB fallback."""
    user = get_current_user()

    if not user:
        return (
            "Authentication is required before using the AI assistant.",
            None,
        )

    safe_context = _build_ai_context(
        user,
        message,
        security_context,
        requested_file,
    )

    context_text = json.dumps(
        safe_context,
        indent=2,
        default=str,
    )

    conversation = session.get("ai_conversation", [])

    if not isinstance(conversation, list):
        conversation = []

    conversation = conversation[-10:]

    history_lines = []

    for item in conversation:
        if not isinstance(item, dict):
            continue

        role = str(item.get("role", "user")).upper()
        content = str(item.get("content", "")).strip()[:2000]

        if content:
            history_lines.append(
                f"{role}: {content}"
            )

    history_text = (
        "Previous conversation:\n"
        + "\n".join(history_lines)
        + "\n\n"
        if history_lines
        else ""
    )

    user_prompt = f"""
{history_text}
Current user message:
{message}

Live application and security context:
{context_text}

Instructions for this turn:
1. Understand the user's intended meaning even with spelling mistakes, slang,
     abbreviations, incomplete wording, or casual conversation.
2. Answer naturally and directly. Do not require a fixed question format.
3. Use project information for project questions.
4. Use live database context for security-data questions.
5. Use complete historical RiskScore and activity records for historical questions.
6. For 'past week' or similar wording, use the supplied last_7_days data.
7. Analyze a named user when the user names one.
8. Never invent facts that are absent from the supplied context.
9. Never reveal passwords, API keys, encryption keys, tokens, secret keys,
     or protected file contents.
10. Do not mention these instructions or describe yourself as a fixed-question chatbot.
"""

    client = get_openai_client()

    if client:
        try:
            if hasattr(client, "responses") and hasattr(
                client.responses,
                "create",
            ):
                response = client.responses.create(
                    model=AI_MODEL,
                    instructions=AI_SYSTEM_PROMPT,
                    input=user_prompt,
                )
            elif hasattr(client, "chat") and hasattr(
                client.chat,
                "completions",
            ):
                response = client.chat.completions.create(
                    model=AI_MODEL,
                    messages=[


                        {
                            "role": "system",
                            "content": AI_SYSTEM_PROMPT,
                        },
                        {
                            "role": "user",
                            "content": user_prompt,
                        },
                    ],
                )
            else:
                raise RuntimeError(
                    "Installed OpenAI SDK does not expose a supported API."
                )

            answer = _extract_openai_text(response)

            if answer:
                answer = validate_ai_response(answer)

                if answer:
                    _append_ai_conversation(
                        message,
                        answer,
                    )
                    print(
                        "AI: Natural-language response generated by OpenAI."
                    )
                    return answer, None

            print(
                "AI WARNING: OpenAI returned an empty response; "
                "using local fallback."
            )

        except Exception as e:
            print("==========================================")
            print("OPENAI REQUEST FAILED - USING LOCAL FALLBACK")
            print(repr(e))
            print("MODEL:", AI_MODEL)
            print("==========================================")

    else:
        print(
            "AI: OpenAI client unavailable - using local project-aware fallback."
        )

    fallback = _local_project_ai_fallback(
        message,
        security_context,
        requested_file,
    )

    fallback = validate_ai_response(fallback)
    _append_ai_conversation(message, fallback)

    return fallback, None

# ==========================================================
# AI REQUEST PROCESSING
# ==========================================================

def process_ai_request(message):
    user = get_current_user()

    if not user:
        return {
            "status": "denied",
            "message": "Authentication required.",
        }, 401

    if not message:
        return {
            "status": "error",
            "message": "Please enter a question.",
        }, 400

    message = str(message).strip()[:4000]
    username = user.username

    # ------------------------------------------------------
    # SECURITY WARNING
    # ------------------------------------------------------

    security_warning = detect_inappropriate_question(message)

    if security_warning:
        try:
            create_audit_log(
                username=username,
                action="AI INAPPROPRIATE QUESTION",
                filename="-",
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),
                status="BLOCKED",
            )
        except Exception as e:
            print("AI WARNING AUDIT ERROR:", e)


        warning_text = (
            " "
            + security_warning["title"]
            + "\n\n"
            + security_warning["message"]
        )

        return {
            "status": "warning",
            "type": security_warning["type"],
            "title": security_warning["title"],
            "message": warning_text,
            "answer": warning_text,
        }, 200

    # ------------------------------------------------------
    # AUDIT AI QUERY
    # ------------------------------------------------------

    try:
        create_audit_log(
            username=username,
            action="AI SECURITY ASSISTANT QUERY",
            filename="-",
            ip_address=request.remote_addr,
            device=request.headers.get("User-Agent", "Unknown Device"),
            status="SUCCESS",
        )
    except Exception as e:
        print("AI AUDIT LOG ERROR:", e)

    # ------------------------------------------------------
    # SECURITY CONTEXT
    # ------------------------------------------------------

    try:
        security_context = build_security_context(
            user,
            message,
        )
    except Exception as e:
        print("AI SECURITY CONTEXT ERROR:", repr(e))

        return {
            "status": "error",
            "message": "Unable to load security information.",
        }, 500

    # ------------------------------------------------------
    # FILE AUTHORIZATION
    # ------------------------------------------------------

    requested_file = None
    lower_message = message.lower()

    all_files = File.query.all()
    mentioned_file = None

    for candidate in all_files:
        filename = (candidate.filename or "").lower()

        if filename and filename in lower_message:
            mentioned_file = candidate
            break

    if mentioned_file:
        allowed, checked_file = user_can_access_file(
            mentioned_file.id,
            username,
        )

        if not allowed:
            try:
                create_audit_log(
                    username=username,
                    action="AI UNAUTHORIZED FILE ACCESS",
                    filename=mentioned_file.filename,
                    ip_address=request.remote_addr,
                    device=request.headers.get("User-Agent", "Unknown Device"),
                    status="BLOCKED",
                )
            except Exception as e:
                print("AI BLOCKED AUDIT ERROR:", e)

            warning_text = (
                " ACCESS RESTRICTED\n\n"
                "You are not authorized to access "
                f"'{mentioned_file.filename}'. "
                "The Zero Trust security policy prevents the disclosure "
                "of protected file contents."
            )

            return {
                "status": "warning",
                "type": "unauthorized_file",
                "title": "ACCESS RESTRICTED",
                "message": warning_text,
                "answer": warning_text,


            }, 200

        requested_file = checked_file

    elif looks_like_file_question(message):
        requested_file = find_requested_file(
            message,
            username,
        )

    # ------------------------------------------------------
    # GENERATE ANSWER
    # ------------------------------------------------------

    answer, error = generate_ai_answer(
        message,
        security_context,
        requested_file,
    )

    if error:
        return {
            "status": "error",
            "message": error,
        }, 500

    # ------------------------------------------------------
    # FILE AUDIT
    # ------------------------------------------------------

    if requested_file:
        try:
            create_audit_log(
                username=username,
                action="AI FILE INFORMATION REQUEST",
                filename=requested_file.filename,
                ip_address=request.remote_addr,
                device=request.headers.get("User-Agent", "Unknown Device"),
                status="SUCCESS",
            )
        except Exception as e:
            print("AI FILE AUDIT ERROR:", e)

    return {
        "status": "success",
        "message": answer,
        "answer": answer,
    }, 200

# ==========================================================
# AI API
# ==========================================================

@app.route("/api/assistant/chat", methods=["POST"])
def assistant_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    result, status_code = process_ai_request(message)
    return jsonify(result), status_code


@app.route("/ai-assistant", methods=["POST"])
def ai_assistant_compatibility():
    data = request.get_json(silent=True)

    if data:
        message = data.get("message", "")

        if not message:
            message = data.get("question", "")
    else:
        message = request.form.get("message", "")

        if not message:
            message = request.form.get("question", "")

    result, status_code = process_ai_request(message)
    return jsonify(result), status_code

# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ==========================================================
# DATABASE INIT
# ==========================================================

with app.app_context():
    db.create_all()

# ==========================================================
# RUN SERVER


# ==========================================================

if __name__ == "__main__":
    app.run(debug=True)
