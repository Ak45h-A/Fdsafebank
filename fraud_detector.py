"""
fraud_detector.py — Rule-based fraud scoring engine
UPGRADED:
  - Repeat offender detection (merchant flagged 2+ times = +30 score)
  - Blacklisted merchant check (instant CRITICAL if blacklisted)
  - Uses cursor-safe approach that works on both SQLite and PostgreSQL
"""
from datetime import datetime, timedelta

RISKY_MERCHANTS  = ["crypto","bitcoin","gambling","lottery","casino","wire transfer",
                    "anonymous","gift card","forex","darkweb"]
RISKY_LOCATIONS  = ["Unknown","Anonymous VPN","TOR Node","Foreign Server",
                    "North Korea","Offshore"]
SAFE_MERCHANTS   = ["amazon","flipkart","swiggy","zomato","irctc","bigbasket",
                    "phonepe","gpay","paytm","netflix","uber","ola"]


def calculate_fraud_score(account_id, amount, merchant, location):
    from database import get_connection, close, USING_POSTGRES, adapt_query, params_to_pg

    score   = 0
    reasons = []
    conn    = get_connection()

    def _fetchone(q, p=()):
        q2 = adapt_query(q)
        if USING_POSTGRES:
            rows = conn.run(q2, **params_to_pg(p)) if p else conn.run(q2)
            if not rows: return None
            cols = [c["name"] for c in conn.columns]
            return dict(zip(cols, rows[0]))
        else:
            c = conn.cursor(); c.execute(q2, p); row = c.fetchone()
            return dict(row) if row else None

    def _fetchall(q, p=()):
        q2 = adapt_query(q)
        if USING_POSTGRES:
            rows = conn.run(q2, **params_to_pg(p)) if p else conn.run(q2)
            if not rows: return []
            cols = [c["name"] for c in conn.columns]
            return [dict(zip(cols, r)) for r in rows]
        else:
            c = conn.cursor(); c.execute(q2, p)
            return [dict(r) for r in c.fetchall()]

    try:
        ml = merchant.lower()

        # Rule 0 — Blacklisted merchant (instant critical)
        row = _fetchone(
            "SELECT id FROM blacklisted_merchants WHERE LOWER(merchant_name)=?",
            (ml,))
        if row:
            close(conn)
            return 95, [f"Merchant '{merchant}' is blacklisted by SafeBank"]

        # Rule 1 — Amount anomaly vs history
        row = _fetchone(
            "SELECT AVG(amount) as avg FROM transactions WHERE account_id=? AND txn_type='debit'",
            (account_id,))
        if row and row["avg"]:
            avg = row["avg"]
            if amount > avg * 10:
                score += 35; reasons.append(f"Amount is {amount/avg:.0f}x your average spend")
            elif amount > avg * 5:
                score += 20; reasons.append("Amount is unusually high (5x average)")
            elif amount > avg * 3:
                score += 10; reasons.append("Amount is higher than usual")
        else:
            if amount > 50000:
                score += 20; reasons.append("Large amount on new account")

        # Rule 2 — Velocity: too many txns in 5 min
        since = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        row = _fetchone(
            "SELECT COUNT(*) as n FROM transactions WHERE account_id=? AND timestamp>? AND txn_type='debit'",
            (account_id, since))
        n = int(row["n"]) if row else 0
        if n >= 3:
            score += 25; reasons.append(f"{n} transactions in last 5 minutes")

        # Rule 3 — Risky merchant keyword
        for w in RISKY_MERCHANTS:
            if w in ml:
                score += 25; reasons.append(f"High-risk merchant: {merchant}"); break

        # Rule 4 — Risky location
        if location in RISKY_LOCATIONS:
            score += 30; reasons.append(f"Suspicious location: {location}")

        # Rule 5 — Night-time large transaction
        h = datetime.now().hour
        if h < 5 and amount > 10000:
            score += 15; reasons.append(f"Large transaction at {h}:00 AM")

        # Rule 6 — Round number
        if amount >= 10000 and amount % 1000 == 0:
            score += 5; reasons.append("Suspiciously round amount")

        # Rule 7 — Safe merchant (reduce score)
        for w in SAFE_MERCHANTS:
            if w in ml:
                score -= 10; break

        # Rule 8 — Repeat offender: merchant flagged 2+ times before
        rows = _fetchall(
            "SELECT COUNT(*) as n FROM fraud_reports r "
            "JOIN transactions t ON r.txn_id=t.txn_id "
            "WHERE LOWER(t.merchant)=? AND r.status IN ('approved','verification_pending')",
            (ml,))
        repeat_count = int(rows[0]["n"]) if rows else 0
        if repeat_count >= 2:
            score += 30
            reasons.append(f"Merchant has {repeat_count} prior confirmed fraud reports")
        elif repeat_count == 1:
            score += 10
            reasons.append("Merchant has 1 prior fraud report")

    finally:
        close(conn)

    return max(0, min(100, score)), reasons


def get_risk_level(score):
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"
