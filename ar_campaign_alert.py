"""
AR Campaign Alert — Daily Metric Check
=======================================
Runs once daily (e.g. via cron at 08:00 local time).
Checks the previous day's SendGrid events for country=AR campaigns,
then fires a Slack webhook alert for any campaign that breaches thresholds.

Requirements:
    pip install psycopg2-binary requests

Environment variables (set in Render / your cron environment):
    DATABASE_URL   — Render PostgreSQL connection string
    SLACK_WEBHOOK  — Slack Incoming Webhook URL

Thresholds (edit below if needed):
    MIN_SENDS        = 100     minimum recipients to trigger evaluation
    MIN_DELIVERY_PCT = 98.0    delivery rate must be >= this
    MIN_OPEN_PCT     = 50.0    open rate must be >= this
    MAX_SPAM_PCT     = 0.1     spam rate must be <= this
"""

import os
import sys
from datetime import date, timedelta

import psycopg2
import psycopg2.extras
import requests

# ── Thresholds ─────────────────────────────────────────────────────────────────
MIN_SENDS        = 100
MIN_DELIVERY_PCT = 98.0
MIN_OPEN_PCT     = 50.0
MAX_SPAM_PCT     = 0.1

# ── Config from environment ────────────────────────────────────────────────────
DATABASE_URL  = os.environ["DATABASE_URL"]
SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK"]

# ── SQL ────────────────────────────────────────────────────────────────────────
# Aggregates yesterday's events for AR, one row per campaign.
# Only campaigns with sends > MIN_SENDS are evaluated.
QUERY = """
WITH yesterday AS (
    SELECT
        campaign,
        COUNT(*) FILTER (WHERE event = 'processed')   AS sends,
        COUNT(*) FILTER (WHERE event = 'delivered')   AS delivered,
        COUNT(*) FILTER (WHERE event = 'open')        AS opened,
        COUNT(*) FILTER (WHERE event = 'spamreport')  AS spam
    FROM sendgrid_events
    WHERE
        country  = 'ar'
        AND event_ts >= (CURRENT_DATE - INTERVAL '1 day')
        AND event_ts <   CURRENT_DATE
        AND campaign IS NOT NULL
    GROUP BY campaign
)
SELECT
    campaign,
    sends,
    delivered,
    opened,
    spam,
    ROUND(delivered::numeric / NULLIF(sends, 0) * 100, 2) AS delivery_pct,
    ROUND(opened::numeric    / NULLIF(sends, 0) * 100, 2) AS open_pct,
    ROUND(spam::numeric      / NULLIF(sends, 0) * 100, 2) AS spam_pct
FROM yesterday
WHERE sends >= %(min_sends)s
ORDER BY sends DESC;
"""


def check_thresholds(row: dict) -> list[str]:
    """Return a list of human-readable breach descriptions, empty if all OK."""
    breaches = []
    if row["delivery_pct"] is not None and row["delivery_pct"] < MIN_DELIVERY_PCT:
        breaches.append(
            f"📦 *Delivery Rate*: {row['delivery_pct']}% "
            f"_(threshold: ≥{MIN_DELIVERY_PCT}%)_"
        )
    if row["open_pct"] is not None and row["open_pct"] < MIN_OPEN_PCT:
        breaches.append(
            f"📬 *Open Rate*: {row['open_pct']}% "
            f"_(threshold: ≥{MIN_OPEN_PCT}%)_"
        )
    if row["spam_pct"] is not None and row["spam_pct"] > MAX_SPAM_PCT:
        breaches.append(
            f"🚨 *Spam Rate*: {row['spam_pct']}% "
            f"_(threshold: ≤{MAX_SPAM_PCT}%)_"
        )
    return breaches


def build_slack_block(row: dict, breaches: list[str], report_date: date) -> dict:
    """Build a single Slack Block Kit section for one breaching campaign."""
    breach_text = "\n".join(f"  • {b}" for b in breaches)
    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                f"*Campaign:* `{row['campaign']}`\n"
                f"*Date:* {report_date}  |  *Country:* ar  |  "
                f"*Sends:* {row['sends']:,}\n"
                f"{breach_text}"
            ),
        },
    }


def send_slack_alert(alerts: list[dict], report_date: date) -> None:
    """Post a Slack message listing all breaching campaigns."""
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"⚠️ AR Campaign Alert — {report_date}",
                "emoji": True,
            },
        },
        {"type": "divider"},
    ]

    for item in alerts:
        blocks.append(build_slack_block(item["row"], item["breaches"], report_date))
        blocks.append({"type": "divider"})

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Evaluated {len(alerts)} campaign(s) with >{MIN_SENDS} sends. "
                        f"Thresholds: delivery ≥{MIN_DELIVERY_PCT}% | "
                        f"open ≥{MIN_OPEN_PCT}% | spam ≤{MAX_SPAM_PCT}%"
                    ),
                }
            ],
        }
    )

    payload = {"blocks": blocks}
    resp = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
    resp.raise_for_status()
    print(f"Slack alert sent — {len(alerts)} campaign(s) flagged.")


def main() -> None:
    report_date = date.today() - timedelta(days=1)
    print(f"Running AR campaign alert check for {report_date} …")

    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(QUERY, {"min_sends": MIN_SENDS})
            rows = cur.fetchall()
    finally:
        conn.close()

    print(f"  → {len(rows)} AR campaign(s) with >{MIN_SENDS} sends found.")

    alerts = []
    for row in rows:
        breaches = check_thresholds(row)
        if breaches:
            alerts.append({"row": row, "breaches": breaches})
            print(f"  ✗ BREACH  — {row['campaign']} ({len(breaches)} issue(s))")
        else:
            print(f"  ✓ OK      — {row['campaign']}")

    if alerts:
        send_slack_alert(alerts, report_date)
    else:
        print("All campaigns within thresholds. No alert sent.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(1)
