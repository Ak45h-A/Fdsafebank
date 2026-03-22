"""
app.py — SafeBank Web Application
FIXED:
  - Background scheduler thread: auto-refund checks + reminder emails
    run every 60 seconds regardless of whether any admin is logged in.
    Reminders fire every 15 min to receiver automatically.
  - Startup no longer re-creates admin on every restart (safe IF NOT EXISTS check).
  - Ctrl+C / restart: data is always preserved (WAL mode in database.py).
"""
import os
import threading
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, Response)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import initialize_database, migrate_database
from bank import (
    register_user, login_user, get_user_account, get_transactions,
    make_payment, deposit_money, submit_fraud_report,
    get_fraud_reports, admin_process_report, get_all_users,
    delete_user_history, get_verification, get_verifications,
    submit_verification_document, request_video_call,
    admin_process_verification, check_and_auto_refund_expired,
    delete_fraud_report, export_fraud_reports_csv,
    get_blacklisted_merchants, add_blacklisted_merchant,
    remove_blacklisted_merchant, get_login_history,
    create_password_reset, verify_reset_token, reset_password,
    check_and_send_reminders
)

# ── APP SETUP ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "safebank-local-dev-key-2024")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_PERMANENT"] = True
app.config["WTF_CSRF_ENABLED"] = True

csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address,
                  default_limits=["200 per day", "50 per hour"],
                  storage_uri="memory://")

# ── BACKGROUND SCHEDULER ──────────────────────────────────────────────────────
# Runs every 60 seconds in a daemon thread.
# Handles: auto-refund expired verifications + send reminder emails every 15 min.
# This means reminders fire even if no admin is logged in.

_scheduler_started = False

def _background_scheduler():
    """Daemon thread: check and refund expired verifications + send reminders."""
    print("[scheduler] Background task started.")
    while True:
        try:
            refunded = check_and_auto_refund_expired()
            if refunded:
                print(f"[scheduler] Auto-refunded {refunded} expired verification(s).")
            reminded = check_and_send_reminders()
            if reminded:
                print(f"[scheduler] Sent {reminded} reminder email(s).")
        except Exception as e:
            print(f"[scheduler] Error: {e}")
        time.sleep(60)  # run every 60 seconds

def start_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    t = threading.Thread(target=_background_scheduler, daemon=True, name="safebank-scheduler")
    t.start()

# ── STARTUP ───────────────────────────────────────────────────────────────────

def startup():
    from database import USING_POSTGRES, get_connection, close
    try:
        initialize_database()
        migrate_database()
        print("[✓] SafeBank database ready.")
    except Exception as e:
        print(f"[!] DB init error: {e}"); return
    try:
        # Only create admin account if it doesn't already exist
        conn = get_connection()
        if USING_POSTGRES:
            rows = conn.run("SELECT user_id FROM users WHERE email=:p1",
                            p1="admin@safebank.com")
            exists = len(rows) > 0
        else:
            c = conn.cursor()
            c.execute("SELECT user_id FROM users WHERE email=?", ("admin@safebank.com",))
            exists = c.fetchone() is not None
        close(conn)
        if not exists:
            admin_pw = os.environ.get("ADMIN_PASSWORD", "change-me-on-first-login")
            register_user("Bank Admin", "admin@safebank.com", admin_pw,
                          "9999999999", 999999, is_admin=1)
            print("[✓] Admin account created.")
        else:
            print("[✓] Admin account exists — no changes made.")
    except Exception as e:
        print(f"[!] Admin setup error: {e}")

    # Start background scheduler (daemon — stops when main thread stops)
    start_scheduler()

startup()

@app.before_request
def make_session_permanent():
    session.permanent = True

# ── HELPERS ───────────────────────────────────────────────────────────────────

def logged_in_user():
    return session.get("user")

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not logged_in_user():
            flash("Please login first.", "warning")
            return redirect(url_for("user_login"))
        if logged_in_user().get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = logged_in_user()
        if not user:
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        if not user.get("is_admin"):
            flash("Access denied.", "error")
            return redirect(url_for("user_login"))
        return f(*args, **kwargs)
    return wrapper

# ── PUBLIC ROUTES ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    user = logged_in_user()
    if user:
        return redirect(url_for("admin_dashboard") if user.get("is_admin")
                        else url_for("dashboard"))
    return redirect(url_for("user_login"))

# ── USER LOGIN / REGISTER ─────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def user_login():
    if logged_in_user():
        return redirect(url_for("admin_dashboard") if logged_in_user().get("is_admin")
                        else url_for("dashboard"))
    if request.method == "POST":
        result = login_user(
            request.form["email"],
            request.form["password"],
            ip_address=request.remote_addr)
        if result["success"]:
            if result["is_admin"]:
                flash("This is the customer login. Admins use the Admin Portal.", "error")
                return redirect(url_for("admin_login"))
            session["user"] = {
                "user_id":    result["user_id"],
                "full_name":  result["full_name"],
                "email":      result["email"],
                "account_id": result["account_id"],
                "is_admin":   0
            }
            return redirect(url_for("dashboard"))
        flash(result["error"], "error")
    return render_template("login_user.html")


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def admin_login():
    if logged_in_user():
        if logged_in_user().get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        session.clear()
    if request.method == "POST":
        result = login_user(
            request.form["email"],
            request.form["password"],
            ip_address=request.remote_addr)
        if result["success"]:
            if not result["is_admin"]:
                flash("Access denied. Admin only.", "error")
                return render_template("login_admin.html")
            session["user"] = {
                "user_id":    result["user_id"],
                "full_name":  result["full_name"],
                "email":      result["email"],
                "account_id": result["account_id"],
                "is_admin":   1
            }
            return redirect(url_for("admin_dashboard"))
        flash(result["error"], "error")
    return render_template("login_admin.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        result = register_user(
            request.form["full_name"], request.form["email"],
            request.form["password"], request.form.get("phone", ""),
            request.form.get("initial_deposit", 1000), is_admin=0)
        if result["success"]:
            login_result = login_user(
                request.form["email"],
                request.form["password"],
                ip_address=request.remote_addr)
            if login_result["success"]:
                session["user"] = {
                    "user_id":    login_result["user_id"],
                    "full_name":  login_result["full_name"],
                    "email":      login_result["email"],
                    "account_id": login_result["account_id"],
                    "is_admin":   0,
                }
                flash(f"Welcome to SafeBank, {login_result['full_name']}! Your account is ready.", "success")
                return redirect(url_for("dashboard"))
            flash("Account created! Please login.", "success")
            return redirect(url_for("user_login"))
        flash(result["error"], "error")
    return render_template("register.html")


@app.route("/logout")
def logout():
    was_admin = logged_in_user() and logged_in_user().get("is_admin")
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("admin_login") if was_admin else url_for("user_login"))

# ── PASSWORD RESET ────────────────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        result = create_password_reset(request.form.get("email", ""))
        flash(result.get("message", "If that email exists, a reset link has been sent."), "info")
        if result.get("token") and not os.environ.get("MAIL_USER"):
            flash(f"[DEV] Reset link: {request.host_url}reset-password/{result['token']}", "warning")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    row = verify_reset_token(token)
    if not row:
        flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        result = reset_password(token, request.form.get("new_password", ""))
        if result["success"]:
            flash(result["message"], "success")
            return redirect(url_for("user_login"))
        flash(result["error"], "error")
    return render_template("reset_password.html", token=token, user_name=row["full_name"])

# ── USER ROUTES ───────────────────────────────────────────────────────────────

@app.route("/dashboard")
@require_login
def dashboard():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    txns = get_transactions(acc["account_id"], limit=5)
    my_reports  = get_fraud_reports(account_id=acc["account_id"])
    login_hist  = get_login_history(user["user_id"], limit=5)
    pending     = sum(1 for r in my_reports if r["status"] == "pending")
    return render_template("dashboard.html", acc=acc, txns=txns,
                           pending_reports=pending, login_history=login_hist)


@app.route("/transactions")
@require_login
def transactions():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    txns = get_transactions(acc["account_id"], limit=50)
    return render_template("transactions.html", acc=acc, txns=txns)


@app.route("/pay", methods=["GET", "POST"])
@require_login
def pay():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    if request.method == "POST":
        result = make_payment(
            acc["account_id"],
            request.form["amount"],
            request.form["merchant"],
            request.form.get("location", "India"),
            request.form.get("description", ""))
        return render_template("pay.html", acc=acc, result=result, form=request.form)
    return render_template("pay.html", acc=acc, result=None, form=None)


@app.route("/deposit", methods=["GET", "POST"])
@require_login
def deposit():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    if request.method == "POST":
        result = deposit_money(acc["account_id"], request.form["amount"])
        if result["success"]:
            flash("Deposited successfully!", "success")
            return redirect(url_for("dashboard"))
        flash(result["error"], "error")
    return render_template("deposit.html", acc=acc)


@app.route("/report-fraud", methods=["GET", "POST"])
@require_login
def report_fraud():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    all_txns  = get_transactions(acc["account_id"], limit=100)
    # Allow user to report ANY transaction they feel is fraudulent
    reportable = [t for t in all_txns if t["status"] not in ("reversed",)]
    if request.method == "POST":
        result = submit_fraud_report(
            acc["account_id"], user["user_id"],
            request.form["txn_id"],
            request.form["reason"],
            request.form.get("evidence", ""))
        if result["success"]:
            flash(result["message"], "success")
            return redirect(url_for("my_reports"))
        flash(result["error"], "error")
    return render_template("report_fraud.html", acc=acc, refundable=reportable)


@app.route("/my-reports")
@require_login
def my_reports():
    user    = logged_in_user()
    acc     = get_user_account(user["user_id"])
    reports = get_fraud_reports(account_id=acc["account_id"])
    return render_template("my_reports.html", acc=acc, reports=reports)

# ── PUBLIC VERIFICATION PAGE ──────────────────────────────────────────────────

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "bmp"}

def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def _safe_filename(filename):
    """Sanitise filename — keep only safe characters."""
    import re
    name, ext = os.path.splitext(filename)
    name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    return (name or "document") + ext.lower()


@app.route("/verify/<verification_id>", methods=["GET", "POST"])
@csrf.exempt
def verify_page(verification_id):
    ver = get_verification(verification_id)
    if not ver:
        return render_template("verify.html", ver=None,
                               error="Verification link is invalid or expired.")
    result = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "upload_document":
            doc_type   = request.form.get("document_type", "")
            doc_number = request.form.get("document_number", "")
            doc_path   = None

            # Handle real file upload
            file = request.files.get("document_file")
            if file and file.filename and _allowed_file(file.filename):
                safe_name = f"{verification_id[:8]}_{_safe_filename(file.filename)}"
                save_path = os.path.join(UPLOAD_FOLDER, safe_name)
                file.save(save_path)
                doc_path = safe_name   # store just the filename, not full path

            doc_name = doc_number or (file.filename if file else "")
            result = submit_verification_document(
                verification_id, doc_type, doc_name, doc_path)
            ver = get_verification(verification_id)

        elif action == "request_video":
            result = request_video_call(verification_id)
            ver = get_verification(verification_id)

    return render_template("verify.html", ver=ver, result=result, error=None)


# ── ADMIN: View uploaded document ─────────────────────────────────────────────

@app.route("/admin/view-document/<verification_id>")
@require_admin
def admin_view_document(verification_id):
    """Serve the uploaded document file to the admin."""
    from flask import send_from_directory, abort
    ver = get_verification(verification_id)
    if not ver or not ver.get("document_path"):
        flash("No document uploaded for this verification.", "error")
        return redirect(url_for("admin_verifications"))
    filename = ver["document_path"]
    if not os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
        flash("Document file not found on server.", "error")
        return redirect(url_for("admin_verifications"))
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/admin/document-decision/<verification_id>", methods=["POST"])
@require_admin
def admin_document_decision(verification_id):
    """
    Admin reviews uploaded document and decides:
      action=not_fraud  → document valid → cancel report, clear receiver
      action=fraud      → document invalid → immediate refund
    """
    user   = logged_in_user()
    action = request.form.get("action")
    notes  = request.form.get("admin_notes", "")

    if action == "not_fraud":
        result = admin_process_verification(
            verification_id, do_refund=False,
            admin_user_id=user["user_id"],
            notes=notes or "Document verified — receiver confirmed legitimate.")
        flash(result["message"] if result["success"] else result["error"],
              "success" if result["success"] else "error")

    elif action == "fraud":
        result = admin_process_verification(
            verification_id, do_refund=True,
            admin_user_id=user["user_id"],
            notes=notes or "Document rejected — receiver confirmed fraudulent. Refund processed.")
        flash(result["message"] if result["success"] else result["error"],
              "success" if result["success"] else "error")
    else:
        flash("Unknown action.", "error")

    return redirect(url_for("admin_verifications"))

# ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@app.route("/admin")
@require_admin
def admin_dashboard():
    pending       = get_fraud_reports(status_filter="pending")
    approved      = get_fraud_reports(status_filter="approved")
    rejected      = get_fraud_reports(status_filter="rejected")
    verif_pending = get_verifications(status_filter="pending")
    verif_docs    = get_verifications(status_filter="document_uploaded")
    verif_video   = get_verifications(status_filter="video_requested")
    users         = get_all_users()
    blacklist     = get_blacklisted_merchants()
    active_verifications = verif_pending + verif_docs + verif_video
    return render_template("admin_dashboard.html",
                           pending=pending, approved=approved, rejected=rejected,
                           users=users, active_verifications=active_verifications,
                           blacklist=blacklist)


@app.route("/admin/reports")
@require_admin
def admin_reports():
    status  = request.args.get("status", "pending")
    reports = get_fraud_reports(status_filter=status if status != "all" else None)
    return render_template("admin_reports.html", reports=reports, current_status=status)


@app.route("/admin/process/<report_id>", methods=["POST"])
@require_admin
def admin_process(report_id):
    user    = logged_in_user()
    action  = request.form.get("action")
    approve = action == "approve"
    notes   = request.form.get("admin_notes", "")
    result  = admin_process_report(report_id, approve, user["user_id"], notes)
    if result["success"]:
        if result.get("verification_created"):
            flash(f"✅ Fraud confirmed. Verification link created ({result['verification_id']}). "
                  f"Receiver has 1 hour to prove identity. Reminders will be sent every 15 min.",
                  "warning")
            return redirect(url_for("admin_verifications"))
        flash(result["message"], "success" if approve else "warning")
    else:
        flash(result["error"], "error")
    return redirect(url_for("admin_reports", status="pending"))


@app.route("/admin/verifications")
@require_admin
def admin_verifications():
    all_v = get_verifications()
    return render_template("admin_verifications.html", verifications=all_v)


@app.route("/admin/verifications-json")
@require_admin
def admin_verifications_json():
    verifs = get_verifications()
    return jsonify([{
        "verification_id": v["verification_id"],
        "report_id":       v["report_id"],
        "deadline_at":     v["deadline_at"],
        "status":          v["status"]
    } for v in verifs])


@app.route("/admin/verify/<verification_id>", methods=["POST"])
@require_admin
def admin_verify(verification_id):
    user      = logged_in_user()
    do_refund = request.form.get("action") == "refund"
    notes     = request.form.get("admin_notes", "")
    result    = admin_process_verification(verification_id, do_refund, user["user_id"], notes)
    if result["success"]:
        flash(result["message"], "success" if do_refund else "warning")
    else:
        flash(result["error"], "error")
    return redirect(url_for("admin_verifications"))


@app.route("/admin/delete-report/<report_id>", methods=["POST"])
@require_admin
def admin_delete_report(report_id):
    user   = logged_in_user()
    result = delete_fraud_report(report_id, admin_user_id=user["user_id"])
    flash(result["message"] if result["success"] else result["error"],
          "success" if result["success"] else "error")
    return redirect(url_for("admin_reports",
                            status=request.form.get("from_status", "approved")))


@app.route("/admin/users")
@require_admin
def admin_users():
    return render_template("admin_users.html", users=get_all_users())


@app.route("/admin/delete-history/<account_id>", methods=["POST"])
@require_admin
def admin_delete_history(account_id):
    user   = logged_in_user()
    result = delete_user_history(account_id, admin_user_id=user["user_id"])
    flash(result["message"] if result["success"] else result["error"],
          "success" if result["success"] else "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/blacklist", methods=["GET", "POST"])
@require_admin
def admin_blacklist():
    user = logged_in_user()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            result = add_blacklisted_merchant(
                request.form.get("merchant_name", ""),
                request.form.get("reason", ""),
                user["user_id"])
        elif action == "remove":
            result = remove_blacklisted_merchant(
                request.form.get("merchant_id", ""),
                user["user_id"])
        else:
            result = {"success": False, "error": "Unknown action"}
        flash(result["message"] if result["success"] else result["error"],
              "success" if result["success"] else "error")
    merchants = get_blacklisted_merchants()
    return render_template("admin_blacklist.html", merchants=merchants)


@app.route("/admin/export-reports")
@require_admin
def admin_export_reports():
    csv_data = export_fraud_reports_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=fraud_reports.csv"})

# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/balance")
@require_login
def api_balance():
    user = logged_in_user()
    acc  = get_user_account(user["user_id"])
    return jsonify({"balance": acc["balance"]})


@app.route("/api/report-status/<report_id>")
@require_login
def api_report_status(report_id):
    user    = logged_in_user()
    acc     = get_user_account(user["user_id"])
    reports = get_fraud_reports(account_id=acc["account_id"])
    for r in reports:
        if r["report_id"] == report_id:
            return jsonify({"status": r["status"], "admin_notes": r.get("admin_notes", "")})
    return jsonify({"error": "not found"}), 404

# ── DEV QUICK-SWITCH ──────────────────────────────────────────────────────────

@app.route("/dev/as-admin")
def dev_as_admin():
    if not app.debug:
        return "Not available in production.", 403
    from database import get_connection, close
    conn = get_connection()
    c = conn.cursor()
    c.execute("""SELECT u.user_id, u.full_name, u.email, a.account_id
                 FROM users u JOIN accounts a ON u.user_id=a.user_id
                 WHERE u.is_admin=1 LIMIT 1""")
    row = c.fetchone()
    close(conn)
    if not row:
        return "No admin account found.", 404
    session.clear()
    session["user"] = {"user_id": row[0], "full_name": row[1],
                       "email": row[2], "account_id": row[3], "is_admin": 1}
    flash(f"[DEV] Switched to admin: {row[1]}", "warning")
    return redirect(url_for("admin_dashboard"))


@app.route("/dev/as-user")
def dev_as_user():
    if not app.debug:
        return "Not available in production.", 403
    from database import get_connection, close
    conn = get_connection()
    c = conn.cursor()
    c.execute("""SELECT u.user_id, u.full_name, u.email, a.account_id
                 FROM users u JOIN accounts a ON u.user_id=a.user_id
                 WHERE u.is_admin=0 LIMIT 1""")
    row = c.fetchone()
    close(conn)
    if not row:
        return "No regular user found. Register one first.", 404
    session.clear()
    session["user"] = {"user_id": row[0], "full_name": row[1],
                       "email": row[2], "account_id": row[3], "is_admin": 0}
    flash(f"[DEV] Switched to user: {row[1]}", "warning")
    return redirect(url_for("dashboard"))

# ── LOCAL RUN ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("SafeBank running at http://localhost:5000")
    port = int(os.environ.get("PORT", 5000))
    # use_reloader=False prevents startup() running twice in debug mode
    app.run(debug=True, host="0.0.0.0", port=port, use_reloader=False)