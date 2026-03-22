"""
bank.py — Core banking operations
UPGRADED:
  - Account lockout after 5 failed login attempts (15 min lock)
  - Login history logging
  - Password reset token generation + reset
  - Merchant blacklist (add/remove/list)
  - Repeat offender check in fraud scoring
  - Email notifications on: refund, rejection, verification, new report
  - CSV export of fraud reports
  - check_and_send_reminders() for 15-min deadline warnings
"""
import bcrypt, re, uuid, csv, io
from datetime import datetime, timedelta
from database import (get_connection, adapt_query, params_to_pg,
                      commit, rollback, close, USING_POSTGRES)

# ── HELPERS ───────────────────────────────────────────────────────────────────

def gen_id(prefix):
    return f"{prefix}-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def hash_pw(pw):
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_pw(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def fmt(n):
    return f"₹{float(n):,.2f}"

def validate_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()) is not None

def validate_amount(amount):
    try:
        amt = round(float(amount), 2)
    except (ValueError, TypeError):
        return None, "Invalid amount."
    if amt <= 0:
        return None, "Amount must be greater than zero."
    if amt > 1_000_000:
        return None, "Exceeds maximum single-transaction limit of ₹10,00,000."
    return amt, None

def run(conn, query, params=()):
    q = adapt_query(query)
    if USING_POSTGRES:
        return conn.run(q, **params_to_pg(params)) if params else conn.run(q)
    else:
        conn.execute(q, params)

def _pg_fetchone(conn, query, params=()):
    q = adapt_query(query)
    if USING_POSTGRES:
        rows = conn.run(q, **params_to_pg(params)) if params else conn.run(q)
        if not rows: return None
        cols = [c["name"] for c in conn.columns]
        return dict(zip(cols, rows[0]))
    else:
        c = conn.cursor(); c.execute(q, params); row = c.fetchone()
        return dict(row) if row else None

def _pg_fetchall(conn, query, params=()):
    q = adapt_query(query)
    if USING_POSTGRES:
        rows = conn.run(q, **params_to_pg(params)) if params else conn.run(q)
        if not rows: return []
        cols = [c["name"] for c in conn.columns]
        return [dict(zip(cols, r)) for r in rows]
    else:
        c = conn.cursor(); c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

def _write_audit(conn, admin_id, action, target_id=None, detail=None):
    try:
        run(conn,
            "INSERT INTO admin_audit_log (log_id,admin_id,action,target_id,detail,performed_at) VALUES(?,?,?,?,?,?)",
            (gen_id("LOG"), admin_id, action, target_id, detail,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    except Exception as e:
        print(f"[audit] {e}")

def _write_login_log(user_id, ip_address, status):
    """Log every login attempt (success or failure)."""
    try:
        conn = get_connection()
        run(conn,
            "INSERT INTO login_log (log_id,user_id,ip_address,status,created_at) VALUES(?,?,?,?,?)",
            (gen_id("LOG"), user_id, ip_address or "unknown", status,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        commit(conn)
        close(conn)
    except Exception as e:
        print(f"[login_log] {e}")

# ── INTERNAL: process a refund (reusable) ────────────────────────────────────

def _do_refund(conn, account_id, amount, txn_id, report_id, description, admin_notes, admin_user_id="system"):
    acc = _pg_fetchone(conn, "SELECT balance FROM accounts WHERE account_id=?", (account_id,))
    new_bal = round(acc["balance"] + amount, 2)
    run(conn, "UPDATE accounts SET balance=? WHERE account_id=?", (new_bal, account_id))
    ref_tid = gen_id("TXN")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run(conn,
        "INSERT INTO transactions (txn_id,account_id,txn_type,amount,balance_after,description,merchant,location,fraud_score,status) "
        "VALUES(?,?,'reversal',?,?,?,?,?,0,'success')",
        (ref_tid, account_id, amount, new_bal, description, "SafeBank Fraud Team", "HQ"))
    run(conn, "UPDATE transactions SET status='reversed' WHERE txn_id=?", (txn_id,))
    run(conn,
        "UPDATE fraud_reports SET status='approved',reviewed_at=?,reviewed_by=?,admin_notes=?,refund_txn_id=? WHERE report_id=?",
        (now, admin_user_id, admin_notes, ref_tid, report_id))
    return ref_tid, new_bal

# ── USER ──────────────────────────────────────────────────────────────────────

def register_user(full_name, email, password, phone, initial_deposit, is_admin=0):
    if not full_name or not full_name.strip():
        return {"success": False, "error": "Full name is required."}
    if not validate_email(email):
        return {"success": False, "error": "Invalid email address."}
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters."}
    dep, err = validate_amount(initial_deposit)
    if err: return {"success": False, "error": err}
    if dep < 500: return {"success": False, "error": "Minimum opening deposit is ₹500."}

    conn = get_connection()
    try:
        if _pg_fetchone(conn, "SELECT user_id FROM users WHERE email=?", (email.strip().lower(),)):
            return {"success": False, "error": "Email already registered."}
        uid, aid, tid = gen_id("USR"), gen_id("ACC"), gen_id("TXN")
        run(conn,
            "INSERT INTO users (user_id,full_name,email,password_hash,phone,is_admin) VALUES(?,?,?,?,?,?)",
            (uid, full_name.strip(), email.strip().lower(), hash_pw(password), phone, is_admin))
        run(conn, "INSERT INTO accounts (account_id,user_id,balance) VALUES(?,?,?)", (aid, uid, dep))
        run(conn,
            "INSERT INTO transactions (txn_id,account_id,txn_type,amount,balance_after,description,merchant,location) "
            "VALUES(?,?,'credit',?,?,'Initial Deposit','SafeBank','Branch')",
            (tid, aid, dep, dep))
        commit(conn)
        return {"success": True, "user_id": uid, "account_id": aid}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def login_user(email, password, ip_address=None):
    conn = get_connection()
    try:
        row = _pg_fetchone(conn, """
            SELECT u.user_id, u.full_name, u.email, u.password_hash, u.is_admin,
                   u.failed_attempts, u.locked_until,
                   a.account_id, a.balance, a.status as acc_status
            FROM users u JOIN accounts a ON u.user_id = a.user_id
            WHERE u.email=?""", (email.strip().lower(),))
        if not row:
            return {"success": False, "error": "Email not found."}

        # Check lockout
        if row["locked_until"]:
            try:
                lock_dt = datetime.strptime(row["locked_until"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() < lock_dt:
                    mins = int((lock_dt - datetime.now()).total_seconds() / 60) + 1
                    return {"success": False,
                            "error": f"Account locked due to too many failed attempts. Try again in {mins} minute(s)."}
                else:
                    # Lock expired — reset
                    run(conn, "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE user_id=?",
                        (row["user_id"],))
                    commit(conn)
            except Exception:
                pass

        if not check_pw(password, row["password_hash"]):
            attempts = (row["failed_attempts"] or 0) + 1
            if attempts >= 5:
                locked_until = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
                run(conn,
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE user_id=?",
                    (attempts, locked_until, row["user_id"]))
                commit(conn)
                _write_login_log(row["user_id"], ip_address, "locked")
                # Send lockout email notification
                try:
                    from notifier import notify_account_locked
                    notify_account_locked(row["email"], row["full_name"], locked_until)
                except Exception:
                    pass
                return {"success": False,
                        "error": "Too many failed attempts. Account locked for 15 minutes."}
            else:
                run(conn, "UPDATE users SET failed_attempts=? WHERE user_id=?",
                    (attempts, row["user_id"]))
                commit(conn)
                _write_login_log(row["user_id"], ip_address, "failed")
                remaining = 5 - attempts
                return {"success": False,
                        "error": f"Wrong password. {remaining} attempt(s) remaining before lockout."}

        if row["acc_status"] != "active":
            return {"success": False, "error": "Account is not active."}

        # Successful login — reset counter
        run(conn, "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE user_id=?",
            (row["user_id"],))
        commit(conn)
        _write_login_log(row["user_id"], ip_address, "success")
        return {"success": True, **row}
    finally:
        close(conn)


def get_user_account(user_id):
    conn = get_connection()
    try:
        return _pg_fetchone(conn, """
            SELECT a.account_id, a.user_id, a.balance, a.status,
                   u.full_name, u.email, u.phone, u.is_admin
            FROM accounts a JOIN users u ON a.user_id = u.user_id
            WHERE a.user_id=?""", (user_id,))
    finally:
        close(conn)


def get_transactions(account_id, limit=50):
    conn = get_connection()
    try:
        return _pg_fetchall(conn,
            "SELECT * FROM transactions WHERE account_id=? ORDER BY timestamp DESC LIMIT ?",
            (account_id, limit))
    finally:
        close(conn)


def get_login_history(user_id, limit=10):
    """Return last N login events for a user."""
    conn = get_connection()
    try:
        return _pg_fetchall(conn,
            "SELECT * FROM login_log WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit))
    finally:
        close(conn)


# ── PASSWORD RESET ────────────────────────────────────────────────────────────

def create_password_reset(email):
    conn = get_connection()
    try:
        user = _pg_fetchone(conn, "SELECT user_id, full_name, email FROM users WHERE email=?",
                            (email.strip().lower(),))
        if not user:
            # Don't reveal if email exists
            return {"success": True, "message": "If that email exists, a reset link has been sent."}
        token = uuid.uuid4().hex + uuid.uuid4().hex
        expires = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        # Invalidate any existing tokens
        run(conn, "UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user["user_id"],))
        run(conn,
            "INSERT INTO password_resets (token,user_id,expires_at) VALUES(?,?,?)",
            (token, user["user_id"], expires))
        commit(conn)
        try:
            from notifier import notify_password_reset
            notify_password_reset(user["email"], user["full_name"], token)
        except Exception as e:
            print(f"[notifier] {e}")
        return {"success": True, "token": token,
                "message": "If that email exists, a reset link has been sent."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def verify_reset_token(token):
    conn = get_connection()
    try:
        row = _pg_fetchone(conn,
            "SELECT pr.*, u.email, u.full_name FROM password_resets pr "
            "JOIN users u ON pr.user_id=u.user_id "
            "WHERE pr.token=? AND pr.used=0", (token,))
        if not row: return None
        if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
            return None
        return row
    finally:
        close(conn)


def reset_password(token, new_password):
    if not new_password or len(new_password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters."}
    conn = get_connection()
    try:
        row = _pg_fetchone(conn,
            "SELECT * FROM password_resets WHERE token=? AND used=0", (token,))
        if not row:
            return {"success": False, "error": "Invalid or expired reset link."}
        if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
            return {"success": False, "error": "Reset link has expired. Please request a new one."}
        run(conn, "UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE user_id=?",
            (hash_pw(new_password), row["user_id"]))
        run(conn, "UPDATE password_resets SET used=1 WHERE token=?", (token,))
        commit(conn)
        return {"success": True, "message": "Password reset successfully. You can now log in."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


# ── PAYMENT & DEPOSIT ─────────────────────────────────────────────────────────

def make_payment(account_id, amount, merchant, location="India", description=""):
    amount, err = validate_amount(amount)
    if err: return {"success": False, "error": err}
    conn = get_connection()
    try:
        acc = _pg_fetchone(conn, "SELECT balance, status FROM accounts WHERE account_id=?", (account_id,))
        if not acc: return {"success": False, "error": "Account not found"}
        if acc["status"] != "active": return {"success": False, "error": "Account not active"}
        if acc["balance"] < amount:
            return {"success": False, "error": f"Insufficient balance. Available: {fmt(acc['balance'])}"}

        from fraud_detector import calculate_fraud_score, get_risk_level
        score, reasons = calculate_fraud_score(account_id, amount, merchant, location)
        risk = get_risk_level(score)

        if score >= 75:
            tid = gen_id("TXN")
            run(conn,
                "INSERT INTO transactions (txn_id,account_id,txn_type,amount,balance_after,description,merchant,location,fraud_score,status) "
                "VALUES(?,?,'blocked',?,?,?,?,?,?,'blocked')",
                (tid, account_id, amount, acc["balance"],
                 description or f"Payment to {merchant}", merchant, location, score))
            commit(conn)
            return {"success": False, "blocked": True, "txn_id": tid,
                    "fraud_score": score, "risk_level": risk, "reasons": reasons,
                    "error": "Transaction BLOCKED — high fraud risk. Your money is safe."}

        new_bal = round(acc["balance"] - amount, 2)
        status = "flagged" if score >= 25 else "success"
        run(conn, "UPDATE accounts SET balance=? WHERE account_id=?", (new_bal, account_id))
        tid = gen_id("TXN")
        run(conn,
            "INSERT INTO transactions (txn_id,account_id,txn_type,amount,balance_after,description,merchant,location,fraud_score,status) "
            "VALUES(?,?,'debit',?,?,?,?,?,?,?)",
            (tid, account_id, amount, new_bal,
             description or f"Payment to {merchant}", merchant, location, score, status))
        commit(conn)
        return {"success": True, "txn_id": tid, "amount": amount, "new_balance": new_bal,
                "fraud_score": score, "risk_level": risk, "flagged": score >= 25, "reasons": reasons}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def deposit_money(account_id, amount):
    amount, err = validate_amount(amount)
    if err: return {"success": False, "error": err}
    conn = get_connection()
    try:
        acc = _pg_fetchone(conn, "SELECT balance FROM accounts WHERE account_id=?", (account_id,))
        if not acc: return {"success": False, "error": "Account not found."}
        new_bal = round(acc["balance"] + amount, 2)
        run(conn, "UPDATE accounts SET balance=? WHERE account_id=?", (new_bal, account_id))
        tid = gen_id("TXN")
        run(conn,
            "INSERT INTO transactions (txn_id,account_id,txn_type,amount,balance_after,description,merchant,location) "
            "VALUES(?,?,'credit',?,?,'Cash Deposit','ATM/Branch','India')",
            (tid, account_id, amount, new_bal))
        commit(conn)
        return {"success": True, "new_balance": new_bal}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


# ── FRAUD REPORTS ─────────────────────────────────────────────────────────────

def submit_fraud_report(account_id, user_id, txn_id, reason, evidence=""):
    conn = get_connection()
    try:
        txn = _pg_fetchone(conn,
            "SELECT * FROM transactions WHERE txn_id=? AND account_id=?", (txn_id, account_id))
        if not txn: return {"success": False, "error": "Transaction not found."}
        if txn["status"] == "reversed":
            return {"success": False, "error": "This transaction was already refunded."}
        ex = _pg_fetchone(conn,
            "SELECT report_id, status FROM fraud_reports WHERE txn_id=? AND status IN ('pending','approved','verification_pending')",
            (txn_id,))
        if ex:
            if ex["status"] == "approved": return {"success": False, "error": "Already refunded."}
            return {"success": False, "error": "This transaction is already under review."}
        rid = gen_id("RPT")
        run(conn,
            "INSERT INTO fraud_reports (report_id,txn_id,account_id,user_id,reason,evidence,fraud_score) VALUES(?,?,?,?,?,?,?)",
            (rid, txn_id, account_id, user_id, reason, evidence, txn.get("fraud_score", 0)))
        commit(conn)

        # Notify admin of new report
        try:
            from notifier import notify_admin_new_report
            user = _pg_fetchone(conn, "SELECT full_name FROM users WHERE user_id=?", (user_id,))
            admin = _pg_fetchone(conn, "SELECT email FROM users WHERE is_admin=1 LIMIT 1", ())
            if admin and user:
                notify_admin_new_report(
                    admin["email"], user["full_name"],
                    txn["amount"], txn["merchant"], rid)
        except Exception as e:
            print(f"[notifier] {e}")

        return {"success": True, "report_id": rid,
                "message": "Fraud report submitted! Admin will review it shortly."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def get_fraud_reports(account_id=None, status_filter=None):
    conn = get_connection()
    try:
        query = """SELECT r.report_id, r.txn_id, r.account_id, r.user_id, r.reason,
                          r.evidence, r.status, r.fraud_score, r.submitted_at,
                          r.reviewed_at, r.reviewed_by, r.admin_notes, r.refund_txn_id,
                          t.amount, t.merchant, t.timestamp as txn_date, t.location,
                          u.full_name, u.email
                   FROM fraud_reports r
                   JOIN transactions t ON r.txn_id  = t.txn_id
                   JOIN users        u ON r.user_id = u.user_id"""
        params, filters = [], []
        if account_id:    filters.append("r.account_id=?"); params.append(account_id)
        if status_filter: filters.append("r.status=?");     params.append(status_filter)
        if filters: query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY r.submitted_at DESC"
        return _pg_fetchall(conn, query, params)
    finally:
        close(conn)


def export_fraud_reports_csv():
    """Return a CSV string of all fraud reports for admin download."""
    reports = get_fraud_reports()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "report_id","txn_id","full_name","email","merchant","amount",
        "reason","status","fraud_score","submitted_at","reviewed_at",
        "admin_notes","refund_txn_id"
    ])
    writer.writeheader()
    for r in reports:
        writer.writerow({
            "report_id":    r.get("report_id",""),
            "txn_id":       r.get("txn_id",""),
            "full_name":    r.get("full_name",""),
            "email":        r.get("email",""),
            "merchant":     r.get("merchant",""),
            "amount":       r.get("amount",""),
            "reason":       r.get("reason",""),
            "status":       r.get("status",""),
            "fraud_score":  r.get("fraud_score",""),
            "submitted_at": r.get("submitted_at",""),
            "reviewed_at":  r.get("reviewed_at",""),
            "admin_notes":  r.get("admin_notes",""),
            "refund_txn_id":r.get("refund_txn_id",""),
        })
    return output.getvalue()


# ── ADMIN: Process report → creates verification ──────────────────────────────

def admin_process_report(report_id, approve, admin_user_id, admin_notes=""):
    conn = get_connection()
    try:
        rep = _pg_fetchone(conn, """
            SELECT r.report_id, r.txn_id, r.account_id, r.status,
                   r.user_id, t.amount, t.merchant
            FROM fraud_reports r JOIN transactions t ON r.txn_id=t.txn_id
            WHERE r.report_id=?""", (report_id,))
        if not rep: return {"success": False, "error": "Report not found."}
        if rep["status"] != "pending":
            return {"success": False, "error": f"Report already {rep['status']}."}

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if approve:
            vid = gen_id("VRF")
            deadline = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            run(conn,
                "INSERT INTO verifications (verification_id,report_id,txn_id,account_id,merchant,amount,deadline_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (vid, report_id, rep["txn_id"], rep["account_id"],
                 rep["merchant"], rep["amount"], deadline))
            run(conn,
                "UPDATE fraud_reports SET status='verification_pending',reviewed_at=?,reviewed_by=?,admin_notes=? WHERE report_id=?",
                (now, admin_user_id,
                 admin_notes or "Fraud confirmed. Receiver must verify identity within 1 hour.",
                 report_id))
            _write_audit(conn, admin_user_id, "CREATE_VERIFICATION", report_id, f"VRF={vid}")
            commit(conn)

            # Notify receiver via email (merchant field used as receiver email if valid)
            try:
                from notifier import notify_verification_created
                merchant_val = rep["merchant"]
                if validate_email(merchant_val):
                    notify_verification_created(
                        merchant_val, merchant_val, rep["amount"], vid, deadline)
            except Exception as e:
                print(f"[notifier] {e}")

            return {"success": True, "verification_created": True,
                    "verification_id": vid, "deadline": deadline,
                    "message": f"Verification created. Receiver has 1 hour to prove identity. ID: {vid}"}
        else:
            run(conn,
                "UPDATE fraud_reports SET status='rejected',reviewed_at=?,reviewed_by=?,admin_notes=? WHERE report_id=?",
                (now, admin_user_id, admin_notes or "Rejected after review.", report_id))
            _write_audit(conn, admin_user_id, "REJECT_REPORT", report_id, admin_notes)
            commit(conn)

            # Notify reporter of rejection
            try:
                from notifier import notify_report_rejected
                reporter = _pg_fetchone(conn,
                    "SELECT u.email, u.full_name, t.amount, t.merchant "
                    "FROM fraud_reports r "
                    "JOIN users u ON r.user_id=u.user_id "
                    "JOIN transactions t ON r.txn_id=t.txn_id "
                    "WHERE r.report_id=?", (report_id,))
                if reporter:
                    notify_report_rejected(
                        reporter["email"], reporter["full_name"],
                        reporter["amount"], reporter["merchant"],
                        admin_notes)
            except Exception as e:
                print(f"[notifier] {e}")

            return {"success": True, "approved": False, "message": "Report rejected."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


# ── VERIFICATION FLOW ─────────────────────────────────────────────────────────

def get_verification(verification_id):
    conn = get_connection()
    try:
        return _pg_fetchone(conn, """
            SELECT v.*, r.reason as report_reason, r.account_id as reporter_account,
                   u.full_name as reporter_name, u.email as reporter_email
            FROM verifications v
            JOIN fraud_reports r ON v.report_id = r.report_id
            JOIN users u ON r.user_id = u.user_id
            WHERE v.verification_id=?""", (verification_id,))
    finally:
        close(conn)


def get_verifications(status_filter=None):
    conn = get_connection()
    try:
        query = """SELECT v.*, r.reason as report_reason,
                          u.full_name as reporter_name, u.email as reporter_email
                   FROM verifications v
                   JOIN fraud_reports r ON v.report_id = r.report_id
                   JOIN users u ON r.user_id = u.user_id"""
        params = []
        if status_filter:
            query += " WHERE v.status=?"; params.append(status_filter)
        query += " ORDER BY v.created_at DESC"
        return _pg_fetchall(conn, query, params)
    finally:
        close(conn)


def submit_verification_document(verification_id, document_type, document_name, document_path=None):
    conn = get_connection()
    try:
        ver = _pg_fetchone(conn,
            "SELECT * FROM verifications WHERE verification_id=?", (verification_id,))
        if not ver: return {"success": False, "error": "Verification not found."}
        if ver["status"] not in ("pending", "video_requested"):
            return {"success": False, "error": f"Cannot submit document at this stage ({ver['status']})."}
        if datetime.now() > datetime.strptime(ver["deadline_at"], "%Y-%m-%d %H:%M:%S"):
            _auto_refund_verification(conn, verification_id)
            commit(conn)
            return {"success": False, "expired": True,
                    "error": "Verification deadline has passed. Refund has been automatically processed."}
        run(conn,
            "UPDATE verifications SET status='document_uploaded',document_type=?,document_name=?,document_path=? WHERE verification_id=?",
            (document_type, document_name, document_path, verification_id))
        commit(conn)
        return {"success": True,
                "message": "Document submitted successfully. Our team will review within minutes."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def request_video_call(verification_id):
    conn = get_connection()
    try:
        ver = _pg_fetchone(conn,
            "SELECT * FROM verifications WHERE verification_id=?", (verification_id,))
        if not ver: return {"success": False, "error": "Verification not found."}
        if ver["status"] not in ("pending", "document_uploaded"):
            return {"success": False,
                    "error": f"Cannot request video call at this stage ({ver['status']})."}
        if datetime.now() > datetime.strptime(ver["deadline_at"], "%Y-%m-%d %H:%M:%S"):
            _auto_refund_verification(conn, verification_id)
            commit(conn)
            return {"success": False, "expired": True,
                    "error": "Verification deadline has passed. Refund has been automatically processed."}
        run(conn,
            "UPDATE verifications SET status='video_requested',video_requested=1 WHERE verification_id=?",
            (verification_id,))
        commit(conn)
        meet_link = f"https://meet.jit.si/SafeBank-Verify-{verification_id[:8]}"
        return {"success": True, "meet_link": meet_link,
                "message": "Video call requested. Use the link below to join with a bank officer."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def admin_process_verification(verification_id, do_refund, admin_user_id, notes=""):
    conn = get_connection()
    try:
        ver = _pg_fetchone(conn,
            "SELECT * FROM verifications WHERE verification_id=?", (verification_id,))
        if not ver: return {"success": False, "error": "Verification not found."}
        if ver["status"] not in ("pending", "document_uploaded", "video_requested"):
            return {"success": False, "error": f"Verification already resolved: {ver['status']}."}

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if do_refund:
            ref_tid, new_bal = _do_refund(
                conn, ver["account_id"], ver["amount"], ver["txn_id"],
                ver["report_id"],
                f"REFUND: Receiver failed verification for {ver['txn_id']}",
                notes or "Refunded: Receiver identity verification failed.",
                admin_user_id)
            run(conn,
                "UPDATE verifications SET status='rejected',resolved_at=?,admin_notes=? WHERE verification_id=?",
                (now, notes, verification_id))
            _write_audit(conn, admin_user_id, "VERIFICATION_REFUND", verification_id, notes)
            commit(conn)

            # Notify reporter of successful refund
            try:
                from notifier import notify_refund_approved
                reporter = _pg_fetchone(conn,
                    "SELECT u.email, u.full_name FROM fraud_reports r "
                    "JOIN users u ON r.user_id=u.user_id WHERE r.report_id=?",
                    (ver["report_id"],))
                if reporter:
                    notify_refund_approved(
                        reporter["email"], reporter["full_name"],
                        ver["amount"], ver["merchant"], ref_tid)
            except Exception as e:
                print(f"[notifier] {e}")

            return {"success": True, "refunded": True,
                    "message": f"{fmt(ver['amount'])} refunded. Receiver flagged as fraud."}
        else:
            run(conn,
                "UPDATE fraud_reports SET status='rejected',reviewed_at=?,reviewed_by=?,admin_notes=? WHERE report_id=?",
                (now, admin_user_id,
                 notes or "Dismissed: Receiver provided valid identity proof.", ver["report_id"]))
            run(conn,
                "UPDATE verifications SET status='approved',resolved_at=?,admin_notes=? WHERE verification_id=?",
                (now, notes, verification_id))
            _write_audit(conn, admin_user_id, "VERIFICATION_CLEARED", verification_id, notes)
            commit(conn)
            return {"success": True, "refunded": False,
                    "message": "Receiver verified as legitimate. Fraud report dismissed."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def _auto_refund_verification(conn, verification_id):
    ver = _pg_fetchone(conn,
        "SELECT * FROM verifications WHERE verification_id=? AND status IN ('pending','document_uploaded','video_requested')",
        (verification_id,))
    if not ver: return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _do_refund(conn, ver["account_id"], ver["amount"], ver["txn_id"],
               ver["report_id"],
               f"AUTO-REFUND: Verification expired — {ver['txn_id']}",
               "Auto-refunded: Receiver failed to verify identity within 1 hour.",
               "system")
    run(conn,
        "UPDATE verifications SET status='auto_refunded',resolved_at=? WHERE verification_id=?",
        (now, verification_id))

    # Notify reporter of auto-refund
    try:
        from notifier import notify_refund_approved
        reporter = _pg_fetchone(conn,
            "SELECT u.email, u.full_name FROM fraud_reports r "
            "JOIN users u ON r.user_id=u.user_id WHERE r.report_id=?",
            (ver["report_id"],))
        if reporter:
            notify_refund_approved(
                reporter["email"], reporter["full_name"],
                ver["amount"], ver["merchant"], ver["txn_id"])
    except Exception as e:
        print(f"[notifier] {e}")


def check_and_auto_refund_expired():
    conn = get_connection()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expired = _pg_fetchall(conn,
            "SELECT verification_id FROM verifications "
            "WHERE status IN ('pending','document_uploaded','video_requested') AND deadline_at < ?",
            (now,))
        for v in expired:
            _auto_refund_verification(conn, v["verification_id"])
        if expired: commit(conn)
        return len(expired)
    except Exception as e:
        rollback(conn); return 0
    finally:
        close(conn)


def check_and_send_reminders():
    """
    Send reminder emails every 15 minutes to receivers who still haven't
    submitted their identity proof. Runs on every admin page load.
    Uses last_reminder_sent column to throttle — only sends if it's been
    >= 15 minutes since the last reminder (or never sent yet).
    """
    conn = get_connection()
    try:
        now_dt   = datetime.now()
        now_str  = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        threshold = (now_dt - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")

        # Pick up all active verifications where:
        #   a) deadline hasn't passed yet
        #   b) no reminder ever sent  OR  last reminder was >15 min ago
        active = _pg_fetchall(conn,
            "SELECT * FROM verifications "
            "WHERE status IN ('pending','video_requested') "
            "AND deadline_at > ? "
            "AND (last_reminder_sent IS NULL OR last_reminder_sent < ?)",
            (now_str, threshold))

        sent = 0
        for v in active:
            try:
                diff_secs = (datetime.strptime(v["deadline_at"], "%Y-%m-%d %H:%M:%S") - now_dt).total_seconds()
                mins_left = max(1, int(diff_secs / 60))
                from notifier import notify_verification_reminder
                if validate_email(v["merchant"]):
                    notify_verification_reminder(
                        v["merchant"], v["merchant"],
                        v["amount"], v["verification_id"], mins_left)
                run(conn,
                    "UPDATE verifications SET last_reminder_sent=? WHERE verification_id=?",
                    (now_str, v["verification_id"]))
                sent += 1
            except Exception as e:
                print(f"[reminder] {e}")

        if sent: commit(conn)
        return sent
    except Exception as e:
        rollback(conn); return 0
    finally:
        close(conn)


# ── ADMIN: Delete resolved fraud report ──────────────────────────────────────

def delete_fraud_report(report_id, admin_user_id):
    conn = get_connection()
    try:
        rep = _pg_fetchone(conn,
            "SELECT status FROM fraud_reports WHERE report_id=?", (report_id,))
        if not rep: return {"success": False, "error": "Report not found."}
        if rep["status"] == "pending":
            return {"success": False, "error": "Cannot delete a pending report — resolve it first."}
        if rep["status"] == "verification_pending":
            return {"success": False, "error": "Cannot delete while verification is in progress."}
        _write_audit(conn, admin_user_id, "DELETE_REPORT", report_id,
                     f"Deleted {rep['status']} report")
        run(conn, "DELETE FROM verifications WHERE report_id=?", (report_id,))
        run(conn, "DELETE FROM fraud_reports WHERE report_id=?", (report_id,))
        commit(conn)
        return {"success": True,
                "message": "Report and verification record permanently deleted."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


# ── ADMIN: User management ────────────────────────────────────────────────────

def get_all_users():
    conn = get_connection()
    try:
        return _pg_fetchall(conn, """
            SELECT u.user_id, u.full_name, u.email, u.phone, u.is_admin,
                   u.failed_attempts, u.locked_until, u.created_at,
                   a.account_id, a.balance, a.status as acc_status
            FROM users u JOIN accounts a ON u.user_id = a.user_id
            ORDER BY u.created_at DESC""", ())
    finally:
        close(conn)


def delete_user_history(account_id, admin_user_id="system"):
    conn = get_connection()
    try:
        rows = _pg_fetchone(conn,
            "SELECT COUNT(*) as n FROM transactions WHERE account_id=?", (account_id,))
        count = int(rows["n"]) if rows and rows["n"] else 0
        _write_audit(conn, admin_user_id, "DELETE_HISTORY", account_id,
                     f"Deleted {count} transactions")
        run(conn, "DELETE FROM fraud_reports WHERE account_id=?", (account_id,))
        run(conn, "DELETE FROM transactions WHERE account_id=?", (account_id,))
        commit(conn)
        return {"success": True,
                "message": f"Deleted {count} transaction(s) and all fraud reports."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


# ── ADMIN: Merchant blacklist ─────────────────────────────────────────────────

def get_blacklisted_merchants():
    conn = get_connection()
    try:
        return _pg_fetchall(conn,
            "SELECT * FROM blacklisted_merchants ORDER BY added_at DESC", ())
    finally:
        close(conn)


def add_blacklisted_merchant(merchant_name, reason, admin_user_id):
    if not merchant_name or not merchant_name.strip():
        return {"success": False, "error": "Merchant name is required."}
    conn = get_connection()
    try:
        existing = _pg_fetchone(conn,
            "SELECT id FROM blacklisted_merchants WHERE LOWER(merchant_name)=?",
            (merchant_name.strip().lower(),))
        if existing:
            return {"success": False, "error": "Merchant is already blacklisted."}
        run(conn,
            "INSERT INTO blacklisted_merchants (id,merchant_name,reason,added_by) VALUES(?,?,?,?)",
            (gen_id("BLK"), merchant_name.strip(), reason, admin_user_id))
        _write_audit(conn, admin_user_id, "BLACKLIST_MERCHANT", merchant_name, reason)
        commit(conn)
        return {"success": True, "message": f"'{merchant_name}' has been blacklisted."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)


def remove_blacklisted_merchant(merchant_id, admin_user_id):
    conn = get_connection()
    try:
        m = _pg_fetchone(conn,
            "SELECT merchant_name FROM blacklisted_merchants WHERE id=?", (merchant_id,))
        if not m: return {"success": False, "error": "Merchant not found in blacklist."}
        run(conn, "DELETE FROM blacklisted_merchants WHERE id=?", (merchant_id,))
        _write_audit(conn, admin_user_id, "UNBLACKLIST_MERCHANT", merchant_id, m["merchant_name"])
        commit(conn)
        return {"success": True, "message": f"'{m['merchant_name']}' removed from blacklist."}
    except Exception as e:
        rollback(conn); return {"success": False, "error": str(e)}
    finally:
        close(conn)