"""
notifier.py — Email notification system for SafeBank
Uses Python's built-in smtplib. Configure via environment variables.

Environment variables:
  MAIL_SERVER   — SMTP host         (default: smtp.gmail.com)
  MAIL_PORT     — SMTP port         (default: 587)
  MAIL_USER     — sender email
  MAIL_PASSWORD — app password / SMTP password
  MAIL_FROM     — display name+addr (default: SafeBank <MAIL_USER>)

For Gmail: enable 2FA → create an App Password → set as MAIL_PASSWORD.
For local dev without email: set MAIL_ENABLED=false to just print to console.
"""
import os
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

MAIL_ENABLED  = os.environ.get("MAIL_ENABLED", "true").lower() != "false"
MAIL_SERVER   = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT     = int(os.environ.get("MAIL_PORT", 587))
MAIL_USER     = os.environ.get("MAIL_USER", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
MAIL_FROM     = os.environ.get("MAIL_FROM", f"SafeBank <{MAIL_USER}>")
BASE_URL      = os.environ.get("BASE_URL", "http://127.0.0.1:5000")


def _send(to_email, subject, html_body):
    """Internal: send email in a background thread so it never blocks requests."""
    if not MAIL_ENABLED or not MAIL_USER or not MAIL_PASSWORD:
        print(f"[MAIL] (disabled) To: {to_email} | Subject: {subject}")
        return

    def _worker():
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = MAIL_FROM
            msg["To"]      = to_email
            msg.attach(MIMEText(html_body, "html"))
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
                s.ehlo()
                s.starttls()
                s.login(MAIL_USER, MAIL_PASSWORD)
                s.sendmail(MAIL_USER, to_email, msg.as_string())
            print(f"[MAIL] Sent → {to_email} | {subject}")
        except Exception as e:
            print(f"[MAIL] Failed → {to_email} | {e}")

    threading.Thread(target=_worker, daemon=True).start()


def _base_template(title, body_html, cta_text=None, cta_url=None):
    cta = ""
    if cta_text and cta_url:
        cta = f"""
        <div style="text-align:center;margin:32px 0;">
          <a href="{cta_url}"
             style="background:#1D9E75;color:#fff;padding:14px 32px;
                    border-radius:8px;text-decoration:none;font-size:15px;
                    font-weight:500;display:inline-block;">
            {cta_text}
          </a>
        </div>"""
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;
                background:#fff;border:1px solid #e5e5e5;border-radius:12px;
                overflow:hidden;">
      <div style="background:#1D9E75;padding:24px 32px;">
        <h1 style="color:#fff;margin:0;font-size:22px;font-weight:600;">
          SafeBank
        </h1>
        <p style="color:#9FE1CB;margin:4px 0 0;font-size:13px;">
          Secure · Trusted · Yours
        </p>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#1a1a1a;margin:0 0 16px;font-size:18px;">{title}</h2>
        {body_html}
        {cta}
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
        <p style="color:#999;font-size:12px;margin:0;">
          This is an automated message from SafeBank. Do not reply to this email.
        </p>
      </div>
    </div>"""


# ── PUBLIC NOTIFICATION FUNCTIONS ─────────────────────────────────────────────

def notify_refund_approved(reporter_email, reporter_name, amount, merchant, txn_id):
    """Tell the reporter their refund has been processed."""
    body = f"""
    <p style="color:#444;line-height:1.6;">Hi <strong>{reporter_name}</strong>,</p>
    <p style="color:#444;line-height:1.6;">
      Great news! Your fraud report has been reviewed and your refund has been
      processed successfully.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Amount refunded</td>
        <td style="padding:10px 14px;color:#1D9E75;font-size:14px;font-weight:600;">
          &#8377;{amount:,.2f}
        </td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Merchant</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{merchant}</td>
      </tr>
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Transaction ID</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;font-family:monospace;">
          {txn_id}
        </td>
      </tr>
    </table>
    <p style="color:#444;line-height:1.6;">
      The amount has been credited back to your account. You can check your
      balance and transaction history by logging into SafeBank.
    </p>"""
    html = _base_template("Refund Approved", body, "View My Account", f"{BASE_URL}/dashboard")
    _send(reporter_email, "SafeBank: Your refund has been processed", html)


def notify_report_rejected(reporter_email, reporter_name, amount, merchant, admin_notes):
    """Tell the reporter their report was rejected."""
    body = f"""
    <p style="color:#444;line-height:1.6;">Hi <strong>{reporter_name}</strong>,</p>
    <p style="color:#444;line-height:1.6;">
      After careful review, your fraud report for the transaction below has been
      marked as not fraudulent and no refund will be issued.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Amount</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">&#8377;{amount:,.2f}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Merchant</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{merchant}</td>
      </tr>
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Admin note</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">
          {admin_notes or 'Rejected after review.'}
        </td>
      </tr>
    </table>
    <p style="color:#444;line-height:1.6;">
      If you believe this decision is incorrect, please contact SafeBank support.
    </p>"""
    html = _base_template("Fraud Report Update", body)
    _send(reporter_email, "SafeBank: Update on your fraud report", html)


def notify_verification_created(receiver_email, merchant, amount, verification_id, deadline):
    """Send verification link to the receiver (merchant/person who got the money)."""
    verify_url = f"{BASE_URL}/verify/{verification_id}"
    body = f"""
    <p style="color:#444;line-height:1.6;">Hello,</p>
    <p style="color:#444;line-height:1.6;">
      A transaction involving your account has been flagged as potentially
      fraudulent. To resolve this, you must verify your identity within
      <strong>1 hour</strong> or the amount will be automatically refunded
      to the reporter.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#fff8e1;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Merchant / Your name</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{merchant}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Amount in question</td>
        <td style="padding:10px 14px;color:#c0392b;font-size:14px;font-weight:600;">
          &#8377;{amount:,.2f}
        </td>
      </tr>
      <tr style="background:#fff8e1;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Deadline</td>
        <td style="padding:10px 14px;color:#c0392b;font-size:14px;">
          {deadline}
        </td>
      </tr>
    </table>
    <p style="color:#444;line-height:1.6;">
      Click the button below to submit your identity document (PAN, Aadhaar,
      Passport, or any government-issued ID) or request a video call with a
      bank officer.
    </p>"""
    html = _base_template(
        "Action Required: Verify Your Identity",
        body,
        "Verify My Identity Now",
        verify_url
    )
    _send(receiver_email, "SafeBank: Urgent — Identity verification required", html)


def notify_verification_reminder(receiver_email, merchant, amount, verification_id, minutes_left):
    """15-minute warning reminder to the receiver."""
    verify_url = f"{BASE_URL}/verify/{verification_id}"
    body = f"""
    <p style="color:#444;line-height:1.6;">Hello,</p>
    <p style="color:#444;line-height:1.6;">
      This is a reminder that you have only <strong>{minutes_left} minutes</strong>
      left to verify your identity for the following transaction.
      If you do not verify before the deadline, the amount will be
      automatically refunded.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#fff3cd;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Merchant</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{merchant}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Amount at risk</td>
        <td style="padding:10px 14px;color:#c0392b;font-size:14px;font-weight:600;">
          &#8377;{amount:,.2f}
        </td>
      </tr>
    </table>"""
    html = _base_template(
        f"Reminder: {minutes_left} minutes left to verify",
        body,
        "Verify Now",
        verify_url
    )
    _send(receiver_email, f"SafeBank: {minutes_left} min remaining — verify identity", html)


def notify_admin_new_report(admin_email, reporter_name, amount, merchant, report_id):
    """Ping admin when a new fraud report is submitted."""
    report_url = f"{BASE_URL}/admin/reports?status=pending"
    body = f"""
    <p style="color:#444;line-height:1.6;">A new fraud report has been submitted and is awaiting your review.</p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Reporter</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{reporter_name}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Merchant</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;">{merchant}</td>
      </tr>
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Amount</td>
        <td style="padding:10px 14px;color:#c0392b;font-size:14px;font-weight:600;">
          &#8377;{amount:,.2f}
        </td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#666;font-size:14px;">Report ID</td>
        <td style="padding:10px 14px;color:#333;font-size:14px;font-family:monospace;">
          {report_id}
        </td>
      </tr>
    </table>"""
    html = _base_template(
        "New Fraud Report Submitted",
        body,
        "Review Report",
        report_url
    )
    _send(admin_email, f"SafeBank Admin: New fraud report from {reporter_name}", html)


def notify_password_reset(user_email, user_name, reset_token):
    """Send password reset link to user."""
    reset_url = f"{BASE_URL}/reset-password/{reset_token}"
    body = f"""
    <p style="color:#444;line-height:1.6;">Hi <strong>{user_name}</strong>,</p>
    <p style="color:#444;line-height:1.6;">
      We received a request to reset your SafeBank password.
      Click the button below to set a new password. This link expires in
      <strong>30 minutes</strong>.
    </p>
    <p style="color:#444;line-height:1.6;">
      If you did not request a password reset, you can safely ignore this email.
      Your account remains secure.
    </p>"""
    html = _base_template(
        "Reset Your Password",
        body,
        "Reset Password",
        reset_url
    )
    _send(user_email, "SafeBank: Password reset request", html)


def notify_account_locked(user_email, user_name, locked_until):
    """Tell user their account was locked due to too many failed attempts."""
    body = f"""
    <p style="color:#444;line-height:1.6;">Hi <strong>{user_name}</strong>,</p>
    <p style="color:#444;line-height:1.6;">
      Your SafeBank account has been temporarily locked due to
      <strong>5 consecutive failed login attempts</strong>.
    </p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#fff3cd;">
        <td style="padding:10px 14px;color:#666;font-size:14px;">Locked until</td>
        <td style="padding:10px 14px;color:#c0392b;font-size:14px;font-weight:600;">
          {locked_until}
        </td>
      </tr>
    </table>
    <p style="color:#444;line-height:1.6;">
      Your account will automatically unlock after 15 minutes.
      If this was not you, please contact SafeBank support immediately.
    </p>"""
    html = _base_template("Account Temporarily Locked", body)
    _send(user_email, "SafeBank: Account locked — suspicious login activity", html)
    