# AssetNode PS Utility - Printer Supply Scanner
# Open source. MIT License.

import smtplib
from email.message import EmailMessage
import asyncio
import json
import sqlite3
import re
import threading
import os
import time
import socket
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from threading import Thread
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd
)

# CONFIGURATION TEST1
# ============================================================

COMMUNITY = "public"
PORT = 161
TIMEOUT = 1
RETRIES = 1
OID_FILE = "oids.json"
DAILY_HISTORY_DAYS = 180
MONTHLY_HISTORY_YEARS = 2
MONTHLY_SNAPSHOTS_PER_MONTH = 2
CLEANUP_90DAY_THRESHOLD = 90



# Load OIDs and DB file from JSON
with open(OID_FILE) as f:
    oid_data = json.load(f)

BASE_OIDS = oid_data.get("BASE_OIDS", {})
MODEL_OIDS = oid_data.get("MODELS", {})
DB_FILE = oid_data.get("DB_FILE", "PrinterSupplies.db")
DB_PRINTERS = oid_data.get("DB_PRINTERS")
EMAIL_CONFIG = oid_data.get("EMAIL_CONFIG", {})
EMAIL_RECIPIENTS = oid_data.get("EMAIL_RECIPIENTS", [])

ALERT_CONFIG = oid_data.get("ALERT_CONFIG", {
    "enabled": False,
    "low_threshold": 25,
    "critical_threshold": 10,
    "monitored_supplies": []
})

SCAN_CONFIG = oid_data.get("SCAN_CONFIG", {
    "interval": 1.0,
    "backup_time": "08:00",
    "auto_scan_enabled": False
})


# ============================================================
# EMAIL ALERT SYSTEM
# ============================================================
def generate_html_alert(alerts=None):
    """
    Generates Apple-style HTML blocks for each printer with low/critical supplies.
    If alerts are provided, only displays those supplies.
    If no alerts, shows a checkmark banner.
    """
    html = """
    <!doctype html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;
            background:#f0f2f5;
            color:#111;
            padding:30px;
            display:flex;
            flex-direction:column;
            align-items:center;
        }

        h2 {
            color:#333;
            margin-bottom:25px;
        }

        .printer-block {
            background: linear-gradient(145deg, #ffffff, #f9f9f9);
            padding:20px;
            border-radius:16px;
            margin-bottom:20px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.08);
            width:350px;
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .printer-block:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 25px rgba(0,0,0,0.12);
        }

        .printer-header {
            font-weight:600;
            font-size:17px;
            margin-bottom:12px;
            color:#222;
        }

        .supply {
            padding:7px 12px;
            border-radius:12px;
            display:inline-block;
            margin:4px 4px 4px 0;
            font-size:14px;
            font-weight:500;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .supply:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }

        .low {
            background: linear-gradient(135deg, #fff8dc, #fff3cd);
            color:#856404;
        }

        .critical {
            background: linear-gradient(135deg, #fce7e7, #f8d7da);
            color:#842029;
        }

        .no-alerts {
            color:#28a745;
            font-weight:600;
            font-size:20px;
            text-align:center;
            margin-top:50px;
            padding:20px 40px;
            background: linear-gradient(135deg, #e6f4ea, #d4edda);
            border-radius:16px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.08);
        }

        @media (max-width: 400px) {
            .printer-block { width: 90%; }
        }
    </style>
    </head>
    <body>
    <h2>🖨️ Printer Supplies Status</h2>
    """

    if alerts:
        # Group alerts by printer
        printers = {}
        for alert in alerts:
            ip = alert["ip"]
            model = alert["model"]
            hostname = alert.get("Hostname", "Unknown Host")
            key = (ip, model, hostname)
            printers.setdefault(key, []).append(alert)

        # Generate HTML for each printer
        for (ip, model, hostname), printer_alerts in printers.items():
            html += f"<div class='printer-block'>"
            html += f"<div class='printer-header'>{model} — {ip} — {hostname}</div>"
            for alert in printer_alerts:
                cls = "critical" if alert["level"] == "CRITICAL" else "low"
                html += f"<span class='supply {cls}'>{alert['supply']}: {alert['value']}%</span>"
            html += "</div>"

    else:
        html += "<p class='no-alerts'>✅ All supplies are within safe levels.</p>"

    html += "</body></html>"
    return html







def send_email_alert(subject: str, body: str, html=False):
    if not EMAIL_RECIPIENTS:
        raise RuntimeError("No email recipients configured")

    msg = EmailMessage()
    msg["From"] = EMAIL_CONFIG["from_address"]
    msg["To"] = ", ".join(EMAIL_RECIPIENTS)
    msg["Subject"] = subject

    if html:
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
        server.send_message(msg)

    print(f"📧 Email sent: {subject}")




def send_test_email(resource_name="Test Resource"):
    # Save test recipient if needed
    try:
        with open(OID_FILE, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data["EMAIL_RECIPIENTS"] = EMAIL_RECIPIENTS
    with open(OID_FILE, "w") as f:
        json.dump(data, f, indent=4)

    html_body = generate_html_alert()
    send_email_alert(
        subject="🧪 Printer Scanner Test Alert",
        body=html_body,
        html=True
    )



def send_alerts(alerts=None):
    """Send alerts always, even if none are low."""
    html_body = generate_html_alert()
    subject = "⚠️ Printer Supply Alert" if alerts else "✅ Printer Supplies OK"
    send_email_alert(
        subject=subject,
        body=html_body,
        html=True
    )


def should_send_scheduled_email():
    """Check if it's time to send a scheduled email based on EMAIL_CONFIG."""
    if not EMAIL_CONFIG.get("schedule_enabled", False):
        return False
    
    try:
        schedule_hour = int(EMAIL_CONFIG.get("schedule_hour", "9"))
        schedule_minute = int(EMAIL_CONFIG.get("schedule_minute", "0"))
        
        now = datetime.now()
        schedule_time = now.replace(hour=schedule_hour, minute=schedule_minute, second=0, microsecond=0)
        
        # Send email if we're within the same minute as the scheduled time
        # or if we're slightly after (to account for scan timing)
        time_diff = now - schedule_time
        
        # Send if we're within 5 minutes after the scheduled time and haven't sent today yet
        if time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= 300:  # 5-minute window
            return True
        
        return False
    except (ValueError, TypeError):
        return False


def get_seconds_until_scheduled_time():
    """Calculate seconds until the next scheduled email time."""
    if not EMAIL_CONFIG.get("schedule_enabled", False):
        return 0
    
    try:
        schedule_hour = int(EMAIL_CONFIG.get("schedule_hour", "9"))
        schedule_minute = int(EMAIL_CONFIG.get("schedule_minute", "0"))
        
        now = datetime.now()
        schedule_time = now.replace(hour=schedule_hour, minute=schedule_minute, second=0, microsecond=0)
        
        # If schedule time has passed for today, schedule for tomorrow
        if now >= schedule_time:
            schedule_time = schedule_time + timedelta(days=1)
        
        # Calculate seconds until schedule time
        time_diff = schedule_time - now
        return int(time_diff.total_seconds())
    except (ValueError, TypeError):
        return 0


def can_send_scheduled_email_today():
    """Check if scheduled email hasn't been sent today already."""
    try:
        # Check last email sent time from oids.json
        with open(OID_FILE, "r") as f:
            data = json.load(f)
        
        last_sent_str = data.get("last_email_sent", "")
        if last_sent_str:
            last_sent = datetime.fromisoformat(last_sent_str)
            if last_sent.date() == datetime.now().date():
                return False
        
        return True
    except Exception:
        return True


def mark_scheduled_email_sent():
    """Mark that scheduled email was sent today in oids.json."""
    try:
        with open(OID_FILE, "r") as f:
            data = json.load(f)
        
        data["last_email_sent"] = datetime.now().isoformat()
        
        with open(OID_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Warning: Could not mark email schedule in oids.json: {e}")




# ============================================================
# SQLITE HELPERS
# ============================================================

def sanitize_column_name(name: str) -> str:
    """
    Sanitize a string to use as a SQLite column name.
    Replaces spaces with underscores, % with pct, and removes invalid characters.
    """
    name = name.strip()
    name = name.replace(" ", "_").replace("%", "pct")
    name = re.sub(r"[^\w]", "", name)
    return name


def get_db_connection(db_path=None):
    """Get a SQLite connection with timeout and WAL mode for concurrent access."""
    if db_path is None:
        db_path = DB_FILE
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path=None):
    """Initialize tables in the selected DB with robust error handling"""
    # Always use PrinterSupplies.db - database name cannot be changed
    db_path = "PrinterSupplies.db"

    try:
        db_dir = Path(db_path).parent
        if db_dir != Path('.') and not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)

        conn = get_db_connection(db_path)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS printer_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TEXT,
                model TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS supply_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                model TEXT,
                supply_name TEXT,
                old_value TEXT,
                new_value TEXT,
                timestamp TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS supply_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                model TEXT,
                supply_name TEXT NOT NULL,
                value TEXT,
                scan_date TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                UNIQUE(ip, supply_name, scan_date)
            )
        """)

        conn.commit()
        conn.close()
        return db_path

    except Exception as e:
        fallback_path = Path(__file__).parent / Path(db_path).name
        print(f"⚠️ Could not create DB at {db_path}: {e}")
        print(f"📁 Using fallback location: {fallback_path}")

        try:
            conn = get_db_connection(str(fallback_path))
            c = conn.cursor()

            c.execute("""
                CREATE TABLE IF NOT EXISTS printer_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp TEXT,
                    model TEXT
                )
            """)

            c.execute("""
                CREATE TABLE IF NOT EXISTS supply_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    model TEXT,
                    supply_name TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp TEXT
                )
            """)

            c.execute("""
                CREATE TABLE IF NOT EXISTS supply_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    model TEXT,
                    supply_name TEXT NOT NULL,
                    value TEXT,
                    scan_date TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    UNIQUE(ip, supply_name, scan_date)
                )
            """)

            conn.commit()
            conn.close()

            try:
                with open(OID_FILE, "r") as f:
                    data = json.load(f)
                data["DB_FILE"] = str(fallback_path)
                with open(OID_FILE, "w") as f:
                    json.dump(data, f, indent=4)
                print(f"✅ Updated oids.json with new DB path: {fallback_path}")
            except Exception as json_err:
                print(f"⚠️ Could not update oids.json: {json_err}")

            return str(fallback_path)

        except Exception as fallback_err:
            raise RuntimeError(f"Failed to create database at both {db_path} and {fallback_path}: {fallback_err}")


def get_last_scan(ip, db_path=None):
    if db_path is None:
        db_path = DB_FILE
    conn = get_db_connection(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM printer_scans WHERE ip = ?", (ip,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {}

    conn = get_db_connection(DB_FILE)
    c = conn.cursor()
    c.execute("PRAGMA table_info(printer_scans)")
    columns = [col[1] for col in c.fetchall()]
    conn.close()

    return dict(zip(columns, row))


def log_supply_change(ip, model, supply_name, old_value, new_value, db_path=None):
    if db_path is None:
        db_path = DB_FILE
    conn = get_db_connection(db_path)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        INSERT INTO supply_changes (ip, model, supply_name, old_value, new_value, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, model, supply_name, old_value, new_value, timestamp))

    conn.commit()
    conn.close()

def create_supply_maintenance_record(ip, model, supply_name, old_value, new_value, db_path=None):
    """
    Create a maintenance record when a supply is consumed (value decreases significantly).
    """
    if db_path is None:
        db_path = DB_FILE
    
    # Only create maintenance record for significant consumption (drop of 5% or more)
    try:
        old_percent = int(str(old_value).replace("%", "").strip())
        new_percent = int(str(new_value).replace("%", "").strip())
        
        if old_percent - new_percent < 5:
            return  # Skip small fluctuations
    except (ValueError, AttributeError):
        return  # Skip if values can't be parsed as percentages
    
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # Ensure printer_maintenance table exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS printer_maintenance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            printer_id INTEGER NOT NULL,
            maintenance_type TEXT NOT NULL,
            description TEXT NOT NULL,
            reported_issue TEXT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            technician TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            cost REAL,
            parts_used TEXT,
            next_due_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Get printer_id from IP
    c.execute("SELECT id FROM printer_scans WHERE ip = ?", (ip,))
    printer_row = c.fetchone()
    
    if not printer_row:
        conn.close()
        return
    
    printer_id = printer_row[0]
    
    # Create maintenance record
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    maintenance_type = "SUPPLY_CONSUMPTION"
    description = f"Supply {supply_name} consumed: {old_value} → {new_value}"
    reported_issue = f"Supply level dropped from {old_value} to {new_value}"
    technician = "System Auto-Detection"
    
    c.execute("""
        INSERT INTO printer_maintenance 
        (printer_id, maintenance_type, description, reported_issue, start_time, technician, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'COMPLETED', ?, ?)
    """, (printer_id, maintenance_type, description, reported_issue, current_time, technician, current_time, current_time))
    
    conn.commit()
    conn.close()

def save_supply_history(ip, model, supplies, db_path=None):
    """
    Save daily supply values.
    If a scan already exists for the same day, overwrite it.
    """
    if db_path is None:
        db_path = DB_FILE

    conn = get_db_connection(db_path)
    c = conn.cursor()

    scan_date = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for supply_name, value in supplies.items():
        if value in ("N/A", None):
            continue

        c.execute("""
            INSERT INTO supply_history (ip, model, supply_name, value, scan_date, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, supply_name, scan_date)
            DO UPDATE SET
                value = excluded.value,
                timestamp = excluded.timestamp
        """, (ip, model, supply_name, value, scan_date, timestamp))

    conn.commit()
    conn.close()
def cleanup_supply_history(db_path=None, verbose=False):
    """
    Retention policy:
    - Under 90 days: Keep ALL daily data (no deletion)
    - 90-180 days: Keep only 2 entries per month (first + last day)
    - Older than 180 days: Delete everything
    
    Args:
        db_path: Path to the database (defaults to DB_FILE)
        verbose: If True, prints debug information
    """
    if db_path is None:
        db_path = DB_FILE

    conn = get_db_connection(db_path)
    c = conn.cursor()

    today = datetime.now().date()
    cutoff_90 = today - timedelta(days=CLEANUP_90DAY_THRESHOLD)   # 90 days ago
    cutoff_180 = today - timedelta(days=DAILY_HISTORY_DAYS)        # 180 days ago

    if verbose:
        print(f"[DEBUG] Cleanup started for: {db_path}")
        print(f"[DEBUG] Today: {today}")
        print(f"[DEBUG] 90-day cutoff: {cutoff_90} (keep all under this)")
        print(f"[DEBUG] 180-day cutoff: {cutoff_180} (delete everything older)")
        
        c.execute("SELECT COUNT(*) FROM supply_history")
        total_count = c.fetchone()[0]
        print(f"[DEBUG] Total records in supply_history: {total_count}")
        
        c.execute("SELECT MIN(scan_date), MAX(scan_date) FROM supply_history")
        date_range = c.fetchone()
        print(f"[DEBUG] Date range in DB: {date_range[0]} to {date_range[1]}")

    deleted_total = 0

    # ------------------------------------------------------------
    # 1️⃣ Delete everything older than 180 days
    # ------------------------------------------------------------
    c.execute("""
        DELETE FROM supply_history
        WHERE scan_date < ?
    """, (cutoff_180.strftime("%Y-%m-%d"),))
    deleted_total += c.rowcount
    if verbose:
        print(f"[DEBUG] Deleted {c.rowcount} records older than 180 days")

    # ------------------------------------------------------------
    # 2️⃣ Reduce 90-180 day range to 2 entries per month
    # ------------------------------------------------------------
    c.execute("""
        SELECT ip, supply_name,
               substr(scan_date, 1, 7) AS ym,
               MIN(scan_date) AS first_day,
               MAX(scan_date) AS last_day
        FROM supply_history
        WHERE scan_date >= ?
          AND scan_date < ?
        GROUP BY ip, supply_name, ym
    """, (
        cutoff_180.strftime("%Y-%m-%d"),
        cutoff_90.strftime("%Y-%m-%d")
    ))

    keep_rows = set()
    for ip, supply, ym, first_day, last_day in c.fetchall():
        keep_rows.add((ip, supply, first_day))
        keep_rows.add((ip, supply, last_day))

    if verbose:
        print(f"[DEBUG] Keep rows (first+last per month for 90-180 day range): {len(keep_rows)}")

    c.execute("""
        SELECT id, ip, supply_name, scan_date
        FROM supply_history
        WHERE scan_date >= ?
          AND scan_date < ?
    """, (
        cutoff_180.strftime("%Y-%m-%d"),
        cutoff_90.strftime("%Y-%m-%d")
    ))

    ids_to_delete = []
    for row_id, ip, supply, scan_date in c.fetchall():
        if (ip, supply, scan_date) not in keep_rows:
            ids_to_delete.append((row_id,))

    if ids_to_delete:
        c.executemany("DELETE FROM supply_history WHERE id = ?", ids_to_delete)
        deleted_total += len(ids_to_delete)
        if verbose:
            print(f"[DEBUG] Deleted {len(ids_to_delete)} mid-history records (keeping first+last per month)")

    conn.commit()
    conn.close()

    if verbose:
        print(f"[DEBUG] Total deleted: {deleted_total}")
    
    return deleted_total


def force_cleanup_supply_history(db_path=None):
    """
    Force cleanup that deletes ALL records older than 180 days.
    Use this to immediately reduce database size when needed.
    """
    if db_path is None:
        db_path = DB_FILE

    conn = get_db_connection(db_path)
    c = conn.cursor()

    today = datetime.now().date()
    cutoff = today - timedelta(days=DAILY_HISTORY_DAYS)

    c.execute("""
        DELETE FROM supply_history
        WHERE scan_date < ?
    """, (cutoff.strftime("%Y-%m-%d"),))
    
    deleted = c.rowcount
    conn.commit()
    conn.close()

    return deleted





def update_printer_hostname(ip, hostname, db_printers_path=None, log_callback=None):
    """Update hostname in the printers database"""
    if db_printers_path is None:
        db_printers_path = DB_PRINTERS
    
    if not db_printers_path:
        return  # No printers database configured
    
    try:
        conn = get_db_connection(db_printers_path)
        c = conn.cursor()
        
        # Check current hostname for printer with matching IP
        c.execute("SELECT hostname FROM printers WHERE ip = ?", (ip,))
        current_hostname = c.fetchone()
        
        if current_hostname and current_hostname[0] == hostname:
            # Skip if hostname is already the same
            message = f"  ⏭️ Skipped hostname update (already same): {ip} -> '{hostname}'"
            print(message)
            if log_callback:
                log_callback(message)
        else:
            # Update hostname for printer with matching IP
            c.execute("UPDATE printers SET hostname = ? WHERE ip = ?", (hostname, ip))
            
            if c.rowcount > 0:
                message = f"  🔄 Updated hostname in printers DB: {ip} -> '{hostname}'"
                print(message)
                if log_callback:
                    log_callback(message)
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        error_msg = f"Error updating hostname in printers database: {e}"
        print(error_msg)
        if log_callback:
            log_callback(f"  ❌ {error_msg}")


def save_scan(ip, full_model, data, db_path=None):
    if db_path is None:
        db_path = DB_FILE
    previous_data = get_last_scan(ip, db_path)
    conn = get_db_connection(db_path)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    changes = []

    for key in data.keys():
        col_name = sanitize_column_name(key)
        try:
            c.execute(f"ALTER TABLE printer_scans ADD COLUMN '{col_name}' TEXT")
        except sqlite3.OperationalError:
            pass

    columns = ['ip', 'timestamp', 'model']
    values = [ip, timestamp, full_model]

    for key, value in data.items():
        col_name = sanitize_column_name(key)
        columns.append(f"'{col_name}'")
        values.append(value)

        if previous_data and col_name in previous_data:
            old_value = previous_data[col_name]
            if old_value != value and old_value is not None:
                changes.append({
                    'supply': key,
                    'old': old_value,
                    'new': value
                })
                log_supply_change(ip, full_model, key, old_value, value)
                # Create maintenance record for supply consumption
                create_supply_maintenance_record(ip, full_model, key, old_value, value)

    c.execute("SELECT id FROM printer_scans WHERE ip = ?", (ip,))
    row = c.fetchone()

    if row:
        set_str = ", ".join([f"{col}=?" for col in columns[1:]])
        sql = f"UPDATE printer_scans SET {set_str} WHERE ip = ?"
        c.execute(sql, values[1:] + [ip])
    else:
        columns_str = ", ".join(columns)
        placeholders = ", ".join(["?"] * len(values))
        sql = f"INSERT INTO printer_scans ({columns_str}) VALUES ({placeholders})"
        c.execute(sql, values)

    conn.commit()
    conn.close()

    return changes


# ============================================================
# SNMP HELPERS
# ============================================================

async def snmp_get(ip: str, oid: str):
    engine = SnmpEngine()
    try:
        error_indication, error_status, _, var_binds = await get_cmd(
            engine,
            CommunityData(COMMUNITY, mpModel=1),
            await UdpTransportTarget.create(
                (ip, PORT),
                timeout=TIMEOUT,
                retries=RETRIES
            ),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if error_indication or error_status:
            return None
        return str(var_binds[0][1])
    finally:
        # Properly close SNMP engine after each request
        engine.transportDispatcher.close_dispatcher()



async def fetch_oids(ip: str, oids: dict) -> dict:
    results = {}
    for name, oid in oids.items():
        results[name] = await snmp_get(ip, oid) or "N/A"
    return results


# ============================================================
# PRINTER DISCOVERY (Subnet Scanner)
# ============================================================

PRINTER_PORTS = [9100, 515, 631]
SNMP_PRINTER_OID = "1.3.6.1.2.1.25.3.5.1.1.1"


def parse_ip_range(ip_range_str):
    """Parse IP range string like '192.168.1.1-254' or '192.168.1.0/24'"""
    ip_range_str = ip_range_str.strip()
    
    if "/" in ip_range_str:
        net = ip_range_str.split("/")[0]
        prefix = int(ip_range_str.split("/")[1])
        if prefix == 24:
            base = ".".join(net.split(".")[:3])
            return [f"{base}.{i}" for i in range(1, 255)]
        return []
    
    if "-" in ip_range_str:
        base, end = ip_range_str.rsplit("-", 1)
        base = base.strip()
        try:
            end_num = int(end)
            if end_num > 255:
                return []
            prefix = ".".join(base.split(".")[:3])
            if end_num == 254:
                return [f"{prefix}.{i}" for i in range(1, 255)]
            else:
                start_num = int(base.split(".")[3])
                return [f"{prefix}.{i}" for i in range(start_num, end_num + 1)]
        except (ValueError, IndexError):
            return []
    
    if ip_range_str.count(".") == 3:
        return [ip_range_str]
    
    return []


async def check_port(ip, port, timeout=1):
    """Check if a port is open on an IP"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_snmp_printer(ip, timeout=1):
    """Check if device responds to SNMP printer OID"""
    try:
        engine = SnmpEngine()
        error_indication, error_status, _, var_binds = await asyncio.wait_for(
            get_cmd(
                engine,
                CommunityData(COMMUNITY, mpModel=1),
                await UdpTransportTarget.create((ip, PORT), timeout=timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(SNMP_PRINTER_OID)),
            ),
            timeout=timeout + 0.5
        )
        engine.transportDispatcher.close_dispatcher()
        if error_indication is None and error_status == 0:
            return True
    except Exception:
        pass
    return False


async def is_printer(ip, log_callback=None):
    """Check if an IP is a printer using ports 9100, 515, 631 and/or SNMP"""
    for port in PRINTER_PORTS:
        if await check_port(ip, port):
            if log_callback:
                log_callback(f"  ✓ Port {port} open on {ip}")
            return True
    
    if await check_snmp_printer(ip):
        if log_callback:
            log_callback(f"  ✓ SNMP printer response on {ip}")
        return True
    
    return False


async def discover_printers(ip_list, log_callback=None, progress_callback=None):
    """Scan a list of IPs for printers"""
    found_printers = []
    total = len(ip_list)
    
    for i, ip in enumerate(ip_list):
        if progress_callback:
            progress_callback(i + 1, total)
        
        if log_callback:
            log_callback(f"Checking {ip}...")
        
        if await is_printer(ip, log_callback):
            found_printers.append(ip)
            if log_callback:
                log_callback(f"  🎉 Printer found at {ip}!")
    
    return found_printers


def compute_percent(current, maximum) -> str:
    try:
        current = int(current)
        maximum = int(maximum)
        if maximum <= 0:
            return "N/A"
        return f"{int((current / maximum) * 100)}%"
    except Exception:
        return "N/A"

# ============================================================
# ALERT CHECKER
# ============================================================

def check_supply_alerts(ip, model, supplies_data, hostname="Unknown Host"):
    """
    Check supply levels and generate alerts if thresholds are crossed.
    Returns a list of alert dictionaries.
    """
    if not ALERT_CONFIG.get("enabled", False):
        return []

    alerts = []
    low_threshold = ALERT_CONFIG.get("low_threshold", 25)
    critical_threshold = ALERT_CONFIG.get("critical_threshold", 10)
    monitored = ALERT_CONFIG.get("monitored_supplies", [])

    for supply_name, value in supplies_data.items():
        # Only check percentage values
        if not supply_name.endswith("%"):
            continue

        # If monitored_supplies is not empty, only check those
        if monitored and supply_name not in monitored:
            continue

        try:
            percent_value = int(value.replace("%", "").strip())
        except (ValueError, AttributeError):
            continue

        level = None
        if percent_value <= critical_threshold:
            level = "CRITICAL"
        elif percent_value <= low_threshold:
            level = "LOW"

        if level:
            alerts.append({
                "level": level,
                "ip": ip,
                "model": model,
                "Hostname": hostname,
                "supply": supply_name,
                "value": percent_value
            })

    return alerts


async def scan_printer(ip: str, log_callback=None, db_path=None):
    """
    Scan a single printer, save data, detect changes and generate alerts.
    Returns (results_dict, alerts_list)
    """
    results = {}

    if log_callback:
        log_callback(f"\n📡 Scanning {ip}")

    base_data = await fetch_oids(ip, BASE_OIDS)
    results.update(base_data)

    hostname = base_data.get("Hostname", "Unknown Host")
    if not hostname or hostname == "N/A":
        hostname = "Unknown Host"
    
    full_descr = base_data.get("Description", "Unknown Model")
    if not full_descr or full_descr == "N/A":
        # Skip printer if no description available
        if log_callback:
            log_callback(f"  ❌ Skipping {ip} — no description/hostname available")
        return {}, []
    
    full_model = re.split(r"[;,]", full_descr)[0].strip()
    
    # Update hostname in printers database
    update_printer_hostname(ip, hostname, db_printers_path=DB_PRINTERS, log_callback=log_callback)

    model_oids = {}
    for oid_model_name in MODEL_OIDS.keys():
        if oid_model_name.lower() == full_model.lower():
            model_oids = MODEL_OIDS[oid_model_name]
            break

    if not model_oids:
        # Use GENERIC model if specific model not found
        if "GENERIC" in MODEL_OIDS:
            model_oids = MODEL_OIDS["GENERIC"]
            if log_callback:
                log_callback(f"  ⚠️ Model '{full_model}' not found in OID list, using GENERIC model")
        else:
            if log_callback:
                log_callback(f"  ❌ Skipping {full_model} — model not recognized and no GENERIC model available")
            return {}, []

    results["Model"] = full_model

    model_data = await fetch_oids(ip, model_oids)
    results.update(model_data)

    # Convert current/max to percentage
    keys = list(results.keys())
    for key in keys:
        if key.endswith("Current"):
            supply_name = key.replace(" Current", "")
            max_key = f"{supply_name} Max"
            percent_key = f"{supply_name} %"
            if max_key in results:
                results[percent_key] = compute_percent(results[key], results[max_key])
                results.pop(key, None)
                results.pop(max_key, None)

    if log_callback:
        for key, value in results.items():
            log_callback(f"  {key}: {value}")

    changes = save_scan(ip, full_model, results, db_path=db_path)
    save_supply_history(ip, full_model, results, db_path=db_path)

    if changes and log_callback:
        log_callback(f"\n  🔄 CHANGES DETECTED:")
        for change in changes:
            log_callback(f"    • {change['supply']}: {change['old']} → {change['new']}")

    # Check for alerts
    alerts = check_supply_alerts(ip, full_model, results, hostname=hostname)
    if alerts and log_callback:
        log_callback(f"\n  ⚠️ ALERTS TRIGGERED:")
        for alert in alerts:
            log_callback(f"    • {alert['level']}: {alert['supply']} at {alert['value']}%")

    return results, alerts


# ============================================================
# GUI APPLICATION
# ============================================================

class PrinterScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AssetNode PS Utility")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)

        self.auto_scanning = False
        self.scan_task = None
        self.loop = None
        self.manual_scan_active = False
        self.stop_requested = False
        self.db_enabled = False
        self.email_scheduler_running = False

        self.create_widgets()
        self.load_ips()
        self.load_alert_config()
        self.load_scan_config()
        
        # Auto-start scanning if enabled
        if self.auto_scan_enabled_var.get():
            self.root.after(1000, self.auto_start_scanning)
        
        # Start email scheduler
        self.start_email_scheduler()

    def auto_start_scanning(self):
        """Auto-start scanning if enabled and conditions are met"""
        if self.auto_scan_enabled_var.get() and not self.auto_scanning:
            self.log("🚀 Auto-starting scan as configured...")
            self.start_scanning()

    def get_db_path(self):
        return self.db_path_var.get()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)  # Changed from 3 to 4

        title_label = ttk.Label(main_frame, text="🖨️ Printer Supply Scanner with Email Alerts",
                                font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        # Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="Scan Controls", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        # Scan interval
        ttk.Label(control_frame, text="Scan Interval:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.interval_var = tk.StringVar(value=str(SCAN_CONFIG.get("interval", 1.0)))
        interval_spinbox = ttk.Spinbox(control_frame, from_=0.1, to=24, increment=0.1,
                                       textvariable=self.interval_var, width=10, format="%.1f")
        interval_spinbox.grid(row=0, column=1, padx=5)
        self.interval_var.trace('w', lambda *args: self.save_scan_config())
        ttk.Label(control_frame, text="hours").grid(row=0, column=2, padx=5, sticky=tk.W)

        # Scan time - split into HH:MM inputs
        ttk.Label(control_frame, text="Scan start time:").grid(row=0, column=3, padx=5, sticky="w")
        
        # Parse current backup time to get default values
        current_backup_time = SCAN_CONFIG.get("backup_time", "08:00")
        if ":" in current_backup_time:
            default_hour, default_minute = current_backup_time.split(":")
        else:
            default_hour, default_minute = "08", "00"
        
        self.backup_hour_var = tk.StringVar(value=default_hour)
        self.backup_minute_var = tk.StringVar(value=default_minute)
        
        # Create a frame to contain the time inputs for tight spacing
        time_frame = ttk.Frame(control_frame)
        time_frame.grid(row=0, column=4, padx=5, sticky="w")
        
        # Enable specific scan time checkbox
        self.enable_specific_time_var = tk.BooleanVar(value=SCAN_CONFIG.get("enable_specific_time", True))
        specific_time_check = ttk.Checkbutton(time_frame, text="At:",
                                             variable=self.enable_specific_time_var,
                                             command=self.on_specific_time_toggle)
        specific_time_check.pack(side=tk.LEFT, padx=(0, 5))
        
        # Hour input
        self.backup_hour_entry = ttk.Entry(time_frame, textvariable=self.backup_hour_var, width=3)
        self.backup_hour_entry.pack(side=tk.LEFT)
        
        # Colon separator
        ttk.Label(time_frame, text=":").pack(side=tk.LEFT, padx=(2, 2))
        
        # Minute input
        self.backup_minute_entry = ttk.Entry(time_frame, textvariable=self.backup_minute_var, width=3)
        self.backup_minute_entry.pack(side=tk.LEFT)
        
        # HH:MM label right next to the inputs
        ttk.Label(time_frame, text="(HH:MM)").pack(side=tk.LEFT, padx=(5, 0))
        
        self.backup_hour_var.trace('w', lambda *args: self.save_scan_config())
        self.backup_minute_var.trace('w', lambda *args: self.save_scan_config())
        self.enable_specific_time_var.trace('w', lambda *args: self.save_scan_config())

        # Auto-scan enabled checkbox
        self.auto_scan_enabled_var = tk.BooleanVar(value=SCAN_CONFIG.get("auto_scan_enabled", False))
        auto_scan_check = ttk.Checkbutton(control_frame, text="Start Auto Scan on Launch",
                                          variable=self.auto_scan_enabled_var,
                                          command=self.save_scan_config)
        auto_scan_check.grid(row=0, column=6, padx=5)

        self.start_button = ttk.Button(control_frame, text="▶ Start Auto Scan",
                                       command=self.start_scanning)
        self.start_button.grid(row=0, column=7, padx=10)

        self.stop_button = ttk.Button(control_frame, text="⏹ Stop",
                                      command=self.stop_scanning, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=7, padx=5)

        self.manual_button = ttk.Button(control_frame, text="🔍 Scan Now",
                                        command=self.manual_scan)
        self.manual_button.grid(row=0, column=8, padx=5)

        save_scan_btn = ttk.Button(control_frame, text="💾 Save Scan Settings",
                                 command=self.save_scan_config_with_feedback)
        save_scan_btn.grid(row=0, column=9, padx=5)

        # Database path
        ttk.Label(control_frame, text="DB File:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.db_path_var = tk.StringVar(value=DB_FILE)
        self.printers_db_path_var = tk.StringVar(value=DB_PRINTERS or "")
        db_entry = ttk.Entry(control_frame, textvariable=self.db_path_var, width=35)
        db_entry.grid(row=1, column=1, columnspan=2, padx=5, sticky=tk.W)


        db_button = ttk.Button(control_frame, text="Browse...", command=self.browse_db)
        db_button.grid(row=1, column=4, padx=5)

        change_button = ttk.Button(control_frame, text="Change DB", command=self.change_db)
        change_button.grid(row=1, column=5, padx=5)

        create_db_button = ttk.Button(control_frame, text="Create New DB", command=self.create_new_db)
        create_db_button.grid(row=1, column=6, padx=5)

        # Printers database path
        ttk.Label(control_frame, text="Printers DB:").grid(row=2, column=0, padx=5, sticky=tk.W)
        printers_db_entry = ttk.Entry(control_frame, textvariable=self.printers_db_path_var, width=35)
        printers_db_entry.grid(row=2, column=1, columnspan=2, padx=5, sticky=tk.W)

        printers_db_button = ttk.Button(control_frame, text="Browse...", command=self.browse_printers_db)
        printers_db_button.grid(row=2, column=3, padx=5)

        change_printers_db_button = ttk.Button(control_frame, text="Change Printers DB", command=self.change_printers_db)
        change_printers_db_button.grid(row=2, column=4, padx=5)

        force_cleanup_btn = ttk.Button(control_frame, text="🧹 Force Cleanup History",
                                      command=self.force_cleanup_history)
        force_cleanup_btn.grid(row=2, column=5, padx=5)

        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(control_frame, textvariable=self.status_var,
                                 font=("Helvetica", 9, "italic"))
        status_label.grid(row=3, column=0, columnspan=10, pady=(10, 0))

        # ============================================================
        # OID TESTING FRAME - ADD THIS NEW SECTION
        # ============================================================
        oid_test_frame = ttk.LabelFrame(main_frame, text="OID Testing", padding="10")
        oid_test_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(oid_test_frame, text="Test IP:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.test_ip_var = tk.StringVar()
        test_ip_entry = ttk.Entry(oid_test_frame, textvariable=self.test_ip_var, width=20)
        test_ip_entry.grid(row=0, column=1, padx=5, sticky=tk.W)

        ttk.Label(oid_test_frame, text="Test OID:").grid(row=0, column=2, padx=5, sticky=tk.W)
        self.test_oid_var = tk.StringVar()
        test_oid_entry = ttk.Entry(oid_test_frame, textvariable=self.test_oid_var, width=40)
        test_oid_entry.grid(row=0, column=3, padx=5, sticky=tk.W)

        test_oid_button = ttk.Button(oid_test_frame, text="🧪 Test OID", command=self.test_oid)
        test_oid_button.grid(row=0, column=4, padx=10)

        ttk.Label(oid_test_frame, text="Result:", font=("Helvetica", 9, "bold")).grid(row=1, column=0, padx=5,
                                                                                      pady=(5, 0), sticky=tk.W)
        self.test_result_var = tk.StringVar(value="No test performed yet")
        result_label = ttk.Label(oid_test_frame, textvariable=self.test_result_var,
                                 font=("Helvetica", 9), foreground="blue")
        result_label.grid(row=1, column=1, columnspan=4, padx=5, pady=(5, 0), sticky=tk.W)

        # Alert Configuration Frame
        alert_frame = ttk.LabelFrame(main_frame, text="Email Alert Configuration", padding="10")
        alert_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        self.alert_enabled_var = tk.BooleanVar(value=False)
        alert_check = ttk.Checkbutton(alert_frame, text="Enable Email Alerts",
                                      variable=self.alert_enabled_var,
                                      command=self.save_alert_config)
        alert_check.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        ttk.Label(alert_frame, text="Low Threshold:").grid(row=0, column=1, padx=5, sticky=tk.W)
        self.low_threshold_var = tk.StringVar(value="25")
        low_spin = ttk.Spinbox(alert_frame, from_=1, to=100, increment=1,
                               textvariable=self.low_threshold_var, width=8)
        low_spin.grid(row=0, column=2, padx=5)
        ttk.Label(alert_frame, text="%").grid(row=0, column=3, sticky=tk.W)

        ttk.Label(alert_frame, text="Critical Threshold:").grid(row=0, column=4, padx=5, sticky=tk.W)
        self.critical_threshold_var = tk.StringVar(value="10")
        crit_spin = ttk.Spinbox(alert_frame, from_=1, to=100, increment=1,
                                textvariable=self.critical_threshold_var, width=8)
        crit_spin.grid(row=0, column=5, padx=5)
        ttk.Label(alert_frame, text="%").grid(row=0, column=6, sticky=tk.W)

        save_alert_btn = ttk.Button(alert_frame, text="Save Alert Settings",
                                    command=self.save_alert_config)
        save_alert_btn.grid(row=0, column=7, padx=10)

        test_Email_btn = ttk.Button(
            alert_frame,
            text="📨 Send Test Email",
            command=self.send_test_email

        )
        test_Email_btn.grid(row=1, column=7, padx=10, pady=5)

        config_btn = ttk.Button(alert_frame, text="Configure Monitored Supplies",
                                command=self.open_supply_config)
        config_btn.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W)

        email_btn = ttk.Button(alert_frame, text="Manage Email Config",
                               command=self.open_email_config)
        email_btn.grid(row=1, column=4, columnspan=4, padx=5, pady=5, sticky=tk.W)

        # OID Management Button
        oid_manage_btn = ttk.Button(alert_frame, text="Manage OIDs",
                                   command=self.open_oid_manager)
        oid_manage_btn.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)

        # IP Management Button
        ip_manage_btn = ttk.Button(alert_frame, text="Manage IPs",
                                   command=self.open_ip_manager)
        ip_manage_btn.grid(row=2, column=2, columnspan=2, padx=5, pady=5, sticky=tk.W)

        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Scan Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD,
                                                  height=20, font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        clear_button = ttk.Button(log_frame, text="Clear Log", command=self.clear_log)
        clear_button.grid(row=1, column=0, pady=(5, 0))

        # Bottom info
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=5, column=0, columnspan=3, pady=(10, 0))

        self.ip_count_var = tk.StringVar(value="IPs loaded: 0")
        ttk.Label(info_frame, textvariable=self.ip_count_var).grid(row=0, column=0, padx=10)

        self.last_scan_var = tk.StringVar(value="Last scan: Never")
        ttk.Label(info_frame, textvariable=self.last_scan_var).grid(row=0, column=1, padx=10)

        self.alert_status_var = tk.StringVar(value="Alerts: Disabled")
        ttk.Label(info_frame, textvariable=self.alert_status_var).grid(row=0, column=2, padx=10)

        # Initialize time field states based on checkbox
        self.on_specific_time_toggle()

    def on_specific_time_toggle(self):
        """Handle specific time checkbox toggle"""
        enabled = self.enable_specific_time_var.get()
        # Enable/disable time input fields
        state = tk.NORMAL if enabled else tk.DISABLED
        self.backup_hour_entry.config(state=state)
        self.backup_minute_entry.config(state=state)
        
        # Log the change for user feedback
        if enabled:
            self.log("⏰ Specific scan time enabled")
        else:
            self.log("⏰ Specific scan time disabled - using interval only")
            
        self.save_scan_config()

    # ============================================================
    # ADD THIS NEW METHOD
    # ============================================================
    def test_oid(self):
        """Test a specific OID against a specific IP address"""
        test_ip = self.test_ip_var.get().strip()
        test_oid = self.test_oid_var.get().strip()

        if not test_ip:
            messagebox.showwarning("Missing IP", "Please enter an IP address to test")
            return

        if not test_oid:
            messagebox.showwarning("Missing OID", "Please enter an OID to test")
            return

        self.test_result_var.set("Testing...")
        self.log(f"\n🧪 Testing OID {test_oid} on {test_ip}")

        def worker():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                result = loop.run_until_complete(snmp_get(test_ip, test_oid))

                loop.close()

                if result is None:
                    self.root.after(0, lambda: self.test_result_var.set("❌ Failed - No response or timeout"))
                    self.root.after(0, lambda: self.log(f"  ❌ OID test failed: No response from {test_ip}"))
                else:
                    self.root.after(0, lambda r=result: self.test_result_var.set(f"✅ Success: {r}"))
                    self.root.after(0, lambda r=result: self.log(f"  ✅ OID test result: {r}"))

            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.test_result_var.set(f"❌ Error: {error_msg}"))
                self.root.after(0, lambda: self.log(f"  ❌ OID test error: {error_msg}"))
                import traceback
                self.root.after(0, lambda t=traceback.format_exc(): self.log(t))

        Thread(target=worker, daemon=True).start()


    def load_alert_config(self):
        """Load alert configuration from oids.json"""
        global ALERT_CONFIG, EMAIL_RECIPIENTS
        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)
                ALERT_CONFIG = data.get("ALERT_CONFIG", ALERT_CONFIG)
                EMAIL_RECIPIENTS = data.get("EMAIL_RECIPIENTS", [])

            self.alert_enabled_var.set(ALERT_CONFIG.get("enabled", False))
            self.low_threshold_var.set(str(ALERT_CONFIG.get("low_threshold", 25)))
            self.critical_threshold_var.set(str(ALERT_CONFIG.get("critical_threshold", 10)))

            status = "Enabled" if ALERT_CONFIG.get("enabled") else "Disabled"
            schedule_status = ""
            if ALERT_CONFIG.get("enabled") and EMAIL_CONFIG.get("schedule_enabled", False):
                schedule_time = f"{EMAIL_CONFIG.get('schedule_hour', '9')}:{EMAIL_CONFIG.get('schedule_minute', '0')}"
                schedule_status = f" (Schedule: {schedule_time})"
            self.alert_status_var.set(f"Alerts: {status} ({len(EMAIL_RECIPIENTS)} recipients){schedule_status})")
        except Exception as e:
            self.log(f"❌ Error loading alert config: {e}")

    def save_alert_config(self):
        """Save alert configuration to oids.json"""
        global ALERT_CONFIG
        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)

            ALERT_CONFIG = {
                "enabled": self.alert_enabled_var.get(),
                "low_threshold": int(self.low_threshold_var.get()),
                "critical_threshold": int(self.critical_threshold_var.get()),
                "monitored_supplies": ALERT_CONFIG.get("monitored_supplies", [])
            }

            data["ALERT_CONFIG"] = ALERT_CONFIG

            with open(OID_FILE, "w") as f:
                json.dump(data, f, indent=4)

            self.log("✅ Alert settings saved")
            status = "Enabled" if ALERT_CONFIG.get("enabled") else "Disabled"
            schedule_status = ""
            if ALERT_CONFIG.get("enabled") and EMAIL_CONFIG.get("schedule_enabled", False):
                schedule_time = f"{EMAIL_CONFIG.get('schedule_hour', '9')}:{EMAIL_CONFIG.get('schedule_minute', '0')}"
                schedule_status = f" (Schedule: {schedule_time})"
            self.alert_status_var.set(f"Alerts: {status} ({len(EMAIL_RECIPIENTS)} recipients){schedule_status})")
            
            # Restart email scheduler with new alert settings
            self.stop_email_scheduler()
            self.start_email_scheduler()
            
            messagebox.showinfo("Success", "Alert settings saved successfully!")
        except Exception as e:
            self.log(f"❌ Error saving alert config: {e}")
            messagebox.showerror("Error", f"Failed to save alert settings: {e}")

    def load_scan_config(self):
        """Load scan configuration from oids.json"""
        global SCAN_CONFIG
        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)
                SCAN_CONFIG = data.get("SCAN_CONFIG", SCAN_CONFIG)

            self.interval_var.set(str(SCAN_CONFIG.get("interval", 1.0)))
            
            # Load backup time and split into hour/minute components
            backup_time = SCAN_CONFIG.get("backup_time", "08:00")
            if ":" in backup_time:
                hour, minute = backup_time.split(":")
            else:
                hour, minute = "08", "00"
            self.backup_hour_var.set(hour)
            self.backup_minute_var.set(minute)
            
            self.auto_scan_enabled_var.set(SCAN_CONFIG.get("auto_scan_enabled", False))
            self.enable_specific_time_var.set(SCAN_CONFIG.get("enable_specific_time", True))

            self.log("✅ Scan configuration loaded")
        except Exception as e:
            self.log(f"❌ Error loading scan config: {e}")

    def save_scan_config(self):
        """Save scan configuration to oids.json"""
        global SCAN_CONFIG
        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)

            try:
                interval = float(self.interval_var.get())
            except ValueError:
                interval = 1.0

            # Combine hour and minute into backup_time format
            backup_time = f"{self.backup_hour_var.get().zfill(2)}:{self.backup_minute_var.get().zfill(2)}"

            SCAN_CONFIG = {
                "interval": interval,
                "backup_time": backup_time,
                "auto_scan_enabled": self.auto_scan_enabled_var.get(),
                "enable_specific_time": self.enable_specific_time_var.get()
            }

            data["SCAN_CONFIG"] = SCAN_CONFIG

            with open(OID_FILE, "w") as f:
                json.dump(data, f, indent=4)

            self.log("✅ Scan settings saved")
        except Exception as e:
            self.log(f"❌ Error saving scan config: {e}")

    def save_scan_config_with_feedback(self):
        """Save scan configuration with user feedback"""
        self.save_scan_config()
        messagebox.showinfo("Success", "Scan settings saved successfully!")

    def open_supply_config(self):
        """Open dialog to configure monitored supplies"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Configure Monitored Supplies")
        dialog.geometry("400x500")

        ttk.Label(dialog, text="Select supplies to monitor for alerts:",
                  font=("Helvetica", 10, "bold")).pack(pady=10, padx=10)

        ttk.Label(dialog, text="(Leave all unchecked to monitor all supplies)",
                  font=("Helvetica", 8, "italic")).pack(pady=(0, 10), padx=10)

        # Get all possible supply types from MODEL_OIDS
        all_supplies = set()
        for model_oids in MODEL_OIDS.values():
            for key in model_oids.keys():
                if "Current" in key or "%" in key:
                    supply_name = key.replace(" Current", " %") if "Current" in key else key
                    all_supplies.add(supply_name)

        frame = ttk.Frame(dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        supply_vars = {}
        current_monitored = ALERT_CONFIG.get("monitored_supplies", [])

        for supply in sorted(all_supplies):
            var = tk.BooleanVar(value=supply in current_monitored)
            supply_vars[supply] = var
            ttk.Checkbutton(scrollable_frame, text=supply, variable=var).pack(anchor=tk.W, padx=5, pady=2)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def save_supplies():
            global ALERT_CONFIG
            selected = [supply for supply, var in supply_vars.items() if var.get()]
            ALERT_CONFIG["monitored_supplies"] = selected

            try:
                with open(OID_FILE, "r") as f:
                    data = json.load(f)
                data["ALERT_CONFIG"] = ALERT_CONFIG
                with open(OID_FILE, "w") as f:
                    json.dump(data, f, indent=4)

                self.log(f"✅ Monitoring {len(selected) if selected else 'all'} supplies")
                messagebox.showinfo("Success", "Monitored supplies updated!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

        ttk.Button(dialog, text="Save", command=save_supplies).pack(pady=10)

    def open_email_config(self):
        """Open dialog to manage email SMTP settings and recipients"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Email Configuration")
        dialog.geometry("500x600")

        # Current config
        smtp_server = EMAIL_CONFIG.get("smtp_server", "")
        smtp_port = EMAIL_CONFIG.get("smtp_port", 587)
        username = EMAIL_CONFIG.get("username", "")
        password = EMAIL_CONFIG.get("password", "")
        from_address = EMAIL_CONFIG.get("from_address", "")
        recipients = EMAIL_RECIPIENTS.copy()
        schedule_enabled = EMAIL_CONFIG.get("schedule_enabled", False)
        schedule_hour = EMAIL_CONFIG.get("schedule_hour", "09")
        schedule_minute = EMAIL_CONFIG.get("schedule_minute", "00")

        # Input fields
        ttk.Label(dialog, text="SMTP Server:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        smtp_entry = ttk.Entry(dialog)
        smtp_entry.pack(fill=tk.X, padx=10)
        smtp_entry.insert(0, smtp_server)

        ttk.Label(dialog, text="SMTP Port:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        port_entry = ttk.Entry(dialog)
        port_entry.pack(fill=tk.X, padx=10)
        port_entry.insert(0, str(smtp_port))

        ttk.Label(dialog, text="Username:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        user_entry = ttk.Entry(dialog)
        user_entry.pack(fill=tk.X, padx=10)
        user_entry.insert(0, username)

        ttk.Label(dialog, text="Password:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        pass_entry = ttk.Entry(dialog, show="*")
        pass_entry.pack(fill=tk.X, padx=10)
        pass_entry.insert(0, password)

        ttk.Label(dialog, text="From Address:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        from_entry = ttk.Entry(dialog)
        from_entry.pack(fill=tk.X, padx=10)
        from_entry.insert(0, from_address)

        ttk.Label(dialog, text="Recipients (one per line):").pack(anchor=tk.W, padx=10, pady=(10, 0))
        recip_text = scrolledtext.ScrolledText(dialog, height=6)
        recip_text.pack(fill=tk.BOTH, padx=10, pady=(0, 10))
        recip_text.insert(tk.END, "\n".join(recipients))

        # Email Scheduling Section
        schedule_frame = ttk.LabelFrame(dialog, text="Email Scheduling", padding="10")
        schedule_frame.pack(fill=tk.X, padx=10, pady=(10, 0))

        schedule_var = tk.BooleanVar(value=schedule_enabled)
        schedule_check = ttk.Checkbutton(schedule_frame, text="Schedule Daily Email (instead of per-scan)",
                                         variable=schedule_var)
        schedule_check.pack(anchor=tk.W, pady=(0, 5))

        # Schedule time frame
        time_frame = ttk.Frame(schedule_frame)
        time_frame.pack(fill=tk.X, pady=5)

        ttk.Label(time_frame, text="Schedule Time:").pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Label(time_frame, text="Hour:").pack(side=tk.LEFT, padx=(10, 2))
        hour_var = tk.StringVar(value=schedule_hour)
        hour_spin = ttk.Spinbox(time_frame, from_=0, to=23, width=3, textvariable=hour_var, format="%02.0f")
        hour_spin.pack(side=tk.LEFT, padx=2)

        ttk.Label(time_frame, text="Minute:").pack(side=tk.LEFT, padx=(10, 2))
        minute_var = tk.StringVar(value=schedule_minute)
        minute_spin = ttk.Spinbox(time_frame, from_=0, to=59, width=3, textvariable=minute_var, format="%02.0f")
        minute_spin.pack(side=tk.LEFT, padx=2)

        # Enable/disable schedule time based on checkbox
        def toggle_schedule_fields():
            state = "normal" if schedule_var.get() else "disabled"
            hour_spin.config(state=state)
            minute_spin.config(state=state)
        
        schedule_var.trace('w', lambda *args: toggle_schedule_fields())
        toggle_schedule_fields()

        # Buttons
        def save_email_config():
            global EMAIL_CONFIG, EMAIL_RECIPIENTS
            try:
                EMAIL_CONFIG = {
                    "smtp_server": smtp_entry.get().strip(),
                    "smtp_port": int(port_entry.get().strip()),
                    "username": user_entry.get().strip(),
                    "password": pass_entry.get().strip(),
                    "from_address": from_entry.get().strip(),
                    "schedule_enabled": schedule_var.get(),
                    "schedule_hour": hour_var.get(),
                    "schedule_minute": minute_var.get()
                }
                EMAIL_RECIPIENTS = [line.strip() for line in recip_text.get("1.0", tk.END).splitlines() if line.strip()]

                with open(OID_FILE, "r") as f:
                    data = json.load(f)
                data["EMAIL_CONFIG"] = EMAIL_CONFIG
                data["EMAIL_RECIPIENTS"] = EMAIL_RECIPIENTS
                with open(OID_FILE, "w") as f:
                    json.dump(data, f, indent=4)

                schedule_status = "enabled" if schedule_var.get() else "disabled"
                self.log(f"✅ Email configuration saved ({len(EMAIL_RECIPIENTS)} recipients, schedule {schedule_status})")
                
                # Restart email scheduler with new settings
                self.stop_email_scheduler()
                self.start_email_scheduler()
                
                messagebox.showinfo("Success", "Email configuration saved successfully!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save email configuration: {e}")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="Save", command=save_email_config).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 5))

    def open_oid_manager(self):
        """Open dialog to manage OID profiles"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage OID Profiles")
        dialog.geometry("800x600")
        
        # Naming scheme info note
        note_text = (
            "OID Naming Convention: For some supply levels, use pairs of OIDs may be necessary:\n"
            "  • '{SupplyName} Current' - the current level value\n"
            "  • '{SupplyName} Max' - the maximum/capacity value\n"
            "  • 'OR if no calc is needed - {SupplyName}' - the plain value\n"
            "  The system automatically computes '{SupplyName} %' from these two values.\n"
            "Example: 'Toner Current', 'Toner Max' → 'Toner %'"
        )
        note_label = ttk.Label(dialog, text=note_text, font=("Helvetica", 9), 
                              foreground="#555", justify=tk.LEFT, padding=10)
        note_label.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        # Load current OID data
        try:
            with open(OID_FILE, "r") as f:
                oid_data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load OID data: {e}")
            dialog.destroy()
            return
        
        base_oids = oid_data.get("BASE_OIDS", {})
        model_oids = oid_data.get("MODELS", {})
        
        # Create notebook for tabs
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Base OIDs tab
        base_frame = ttk.Frame(notebook)
        notebook.add(base_frame, text="Base OIDs")
        
        # Model OIDs tab
        model_frame = ttk.Frame(notebook)
        notebook.add(model_frame, text="Model Profiles")
        
        # === Base OIDs Tab ===
        base_label = ttk.Label(base_frame, text="Base OIDs (Used for all printers)", 
                              font=("Helvetica", 10, "bold"))
        base_label.pack(pady=10)
        
        # Create treeview for base OIDs
        base_tree_frame = ttk.Frame(base_frame)
        base_tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        base_columns = ("Name", "OID")
        base_tree = ttk.Treeview(base_tree_frame, columns=base_columns, show="headings", height=10)
        
        for col in base_columns:
            base_tree.heading(col, text=col)
            base_tree.column(col, width=200)
        
        base_scrollbar = ttk.Scrollbar(base_tree_frame, orient="vertical", command=base_tree.yview)
        base_tree.configure(yscrollcommand=base_scrollbar.set)
        
        base_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        base_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate base OIDs
        for name, oid in base_oids.items():
            base_tree.insert("", tk.END, values=(name, oid))
        
        # Base OIDs buttons
        base_btn_frame = ttk.Frame(base_frame)
        base_btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def add_base_oid():
            self.edit_oid_dialog(dialog, base_tree, "Base OID")
        
        def edit_base_oid():
            selection = base_tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an OID to edit")
                return
            item = base_tree.item(selection[0])
            self.edit_oid_dialog(dialog, base_tree, "Base OID", item['values'])
        
        def delete_base_oid():
            selection = base_tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an OID to delete")
                return
            if messagebox.askyesno("Confirm", "Delete selected OID?"):
                base_tree.delete(selection[0])
        
        ttk.Button(base_btn_frame, text="Add Base OID", command=add_base_oid).pack(side=tk.LEFT, padx=5)
        ttk.Button(base_btn_frame, text="Edit Base OID", command=edit_base_oid).pack(side=tk.LEFT, padx=5)
        ttk.Button(base_btn_frame, text="Delete Base OID", command=delete_base_oid).pack(side=tk.LEFT, padx=5)
        
        # === Model Profiles Tab ===
        model_label = ttk.Label(model_frame, text="Model-Specific OID Profiles", 
                               font=("Helvetica", 10, "bold"))
        model_label.pack(pady=10)
        
        # Create paned window for model profiles
        model_paned = ttk.PanedWindow(model_frame, orient=tk.HORIZONTAL)
        model_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left side - Model list
        model_list_frame = ttk.Frame(model_paned)
        model_paned.add(model_list_frame, weight=1)
        
        ttk.Label(model_list_frame, text="Printer Models", font=("Helvetica", 9, "bold")).pack(pady=5)
        
        model_list = tk.Listbox(model_list_frame)
        model_list.pack(fill=tk.BOTH, expand=True, padx=5)
        
        for model_name in model_oids.keys():
            model_list.insert(tk.END, model_name)
        
        # Right side - Model OIDs
        model_detail_frame = ttk.Frame(model_paned)
        model_paned.add(model_detail_frame, weight=2)
        
        ttk.Label(model_detail_frame, text="OIDs for Selected Model", 
                 font=("Helvetica", 9, "bold")).pack(pady=5)
        
        model_tree_frame = ttk.Frame(model_detail_frame)
        model_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        
        model_columns = ("Name", "OID")
        model_tree = ttk.Treeview(model_tree_frame, columns=model_columns, show="headings", height=10)
        
        for col in model_columns:
            model_tree.heading(col, text=col)
            model_tree.column(col, width=200)
        
        model_scrollbar = ttk.Scrollbar(model_tree_frame, orient="vertical", command=model_tree.yview)
        model_tree.configure(yscrollcommand=model_scrollbar.set)
        
        model_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        model_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        def on_model_select(event):
            selection = model_list.curselection()
            if selection:
                model_name = model_list.get(selection[0])
                model_tree.delete(*model_tree.get_children())
                for name, oid in model_oids.get(model_name, {}).items():
                    model_tree.insert("", tk.END, values=(name, oid))
        
        model_list.bind("<<ListboxSelect>>", on_model_select)
        
        # Model profile buttons
        model_btn_frame = ttk.Frame(model_detail_frame)
        model_btn_frame.pack(fill=tk.X, padx=5, pady=10)
        
        def add_model():
            self.add_model_dialog(dialog, model_list, model_oids)
        
        def edit_model():
            selection = model_list.curselection()
            if not selection:
                messagebox.showwarning("Selection", "Please select a model to edit")
                return
            model_name = model_list.get(selection[0])
            self.edit_model_dialog(dialog, model_list, model_oids, model_name)
        
        def delete_model():
            selection = model_list.curselection()
            if not selection:
                messagebox.showwarning("Selection", "Please select a model to delete")
                return
            model_name = model_list.get(selection[0])
            if messagebox.askyesno("Confirm", f"Delete model profile '{model_name}'?"):
                del model_oids[model_name]
                model_list.delete(selection[0])
                model_tree.delete(*model_tree.get_children())
        
        def add_model_oid():
            selection = model_list.curselection()
            if not selection:
                messagebox.showwarning("Selection", "Please select a model first")
                return
            model_name = model_list.get(selection[0])
            self.edit_oid_dialog(dialog, model_tree, "Model OID", model_name=model_name, model_oids=model_oids)
        
        def edit_model_oid():
            selection = model_tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an OID to edit")
                return
            model_selection = model_list.curselection()
            if not model_selection:
                messagebox.showwarning("Selection", "Please select a model first")
                return
            model_name = model_list.get(model_selection[0])
            item = model_tree.item(selection[0])
            self.edit_oid_dialog(dialog, model_tree, "Model OID", item['values'], model_name, model_oids)
        
        def delete_model_oid():
            selection = model_tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an OID to delete")
                return
            
            model_selection = model_list.curselection()
            if not model_selection:
                messagebox.showwarning("Selection", "Please select a model first")
                return
            
            model_name = model_list.get(model_selection[0])
            item = model_tree.item(selection[0])
            oid_name = item['values'][0]
            
            if messagebox.askyesno("Confirm", "Delete selected OID?"):
                # Remove from model_oids dictionary
                if model_name in model_oids and oid_name in model_oids[model_name]:
                    del model_oids[model_name][oid_name]
                model_tree.delete(selection[0])
        
        # Model management buttons
        model_mgmt_frame = ttk.Frame(model_frame)
        model_mgmt_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(model_mgmt_frame, text="Add Model", command=add_model).pack(side=tk.LEFT, padx=5)
        ttk.Button(model_mgmt_frame, text="Edit Model", command=edit_model).pack(side=tk.LEFT, padx=5)
        ttk.Button(model_mgmt_frame, text="Delete Model", command=delete_model).pack(side=tk.LEFT, padx=5)
        
        # Model OID buttons
        ttk.Button(model_btn_frame, text="Add OID", command=add_model_oid).pack(side=tk.LEFT, padx=5)
        ttk.Button(model_btn_frame, text="Edit OID", command=edit_model_oid).pack(side=tk.LEFT, padx=5)
        ttk.Button(model_btn_frame, text="Delete OID", command=delete_model_oid).pack(side=tk.LEFT, padx=5)
        
        # Save/Cancel buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def save_oids():
            try:
                # Collect base OIDs
                new_base_oids = {}
                for item in base_tree.get_children():
                    values = base_tree.item(item)['values']
                    new_base_oids[values[0]] = values[1]
                
                # Collect model OIDs - we need to store the current state properly
                # Create a temporary storage for model OID changes
                model_oids_temp = {}
                
                # Store the current model OID data
                for model_name in model_oids.keys():
                    model_oids_temp[model_name] = model_oids[model_name].copy()
                
                # Save to file
                oid_data["BASE_OIDS"] = new_base_oids
                oid_data["MODELS"] = model_oids_temp
                
                with open(OID_FILE, "w") as f:
                    json.dump(oid_data, f, indent=4)
                
                # Reload global variables
                global BASE_OIDS, MODEL_OIDS
                BASE_OIDS = new_base_oids
                MODEL_OIDS = model_oids_temp
                
                self.log("✅ OID profiles saved successfully")
                messagebox.showinfo("Success", "OID profiles saved successfully!")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save OID profiles: {e}")
        
        ttk.Button(btn_frame, text="Save All Changes", command=save_oids).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def edit_oid_dialog(self, parent_dialog, tree, oid_type, existing_values=None, model_name=None, model_oids=None):
        """Dialog for adding/editing individual OIDs"""
        dialog = tk.Toplevel(parent_dialog)
        dialog.title(f"{'Edit' if existing_values else 'Add'} {oid_type}")
        dialog.geometry("400x200")
        dialog.transient(parent_dialog)
        dialog.grab_set()
        
        old_name = existing_values[0] if existing_values else ""
        
        # Name field
        ttk.Label(dialog, text="OID Name:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        name_var = tk.StringVar(value=old_name)
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # OID field
        ttk.Label(dialog, text="OID Value:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        oid_var = tk.StringVar(value=existing_values[1] if existing_values else "")
        oid_entry = ttk.Entry(dialog, textvariable=oid_var, width=40)
        oid_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Buttons
        def save():
            name = name_var.get().strip()
            oid = oid_var.get().strip()
            
            if not name or not oid:
                messagebox.showwarning("Invalid Input", "Both name and OID are required")
                return
            
            # Handle model OID updates
            if model_name and model_oids is not None:
                if existing_values:
                    # Update existing OID in model_oids
                    if old_name != name:
                        # Name changed, remove old and add new
                        if model_name in model_oids and old_name in model_oids[model_name]:
                            del model_oids[model_name][old_name]
                    model_oids[model_name][name] = oid
                else:
                    # Add new OID to model_oids
                    if model_name not in model_oids:
                        model_oids[model_name] = {}
                    model_oids[model_name][name] = oid
            
            if existing_values:
                # Update existing item in tree
                selection = tree.selection()
                if selection:
                    tree.item(selection[0], values=(name, oid))
            else:
                # Add new item to tree
                tree.insert("", tk.END, values=(name, oid))
            
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Focus on name field
        name_entry.focus()

    def add_model_dialog(self, parent_dialog, model_list, model_oids):
        """Dialog for adding new model profiles"""
        dialog = tk.Toplevel(parent_dialog)
        dialog.title("Add Model Profile")
        dialog.geometry("400x150")
        dialog.transient(parent_dialog)
        dialog.grab_set()
        
        # Model name field
        ttk.Label(dialog, text="Model Name:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        name_var = tk.StringVar()
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Copy from existing model option
        ttk.Label(dialog, text="Copy OIDs from:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        copy_var = tk.StringVar()
        copy_combo = ttk.Combobox(dialog, textvariable=copy_var, width=37)
        copy_combo['values'] = list(model_oids.keys())
        copy_combo.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Buttons
        def save():
            name = name_var.get().strip()
            
            if not name:
                messagebox.showwarning("Invalid Input", "Model name is required")
                return
            
            if name in model_oids:
                messagebox.showwarning("Duplicate", "Model already exists")
                return
            
            # Add to model_oids
            if copy_var.get() and copy_var.get() in model_oids:
                model_oids[name] = model_oids[copy_var.get()].copy()
            else:
                model_oids[name] = {}
            
            model_list.insert(tk.END, name)
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Add Model", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        name_entry.focus()

    def edit_model_dialog(self, parent_dialog, model_list, model_oids, model_name):
        """Dialog for editing model name"""
        dialog = tk.Toplevel(parent_dialog)
        dialog.title("Edit Model Profile")
        dialog.geometry("400x120")
        dialog.transient(parent_dialog)
        dialog.grab_set()
        
        # Model name field
        ttk.Label(dialog, text="Model Name:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        name_var = tk.StringVar(value=model_name)
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Buttons
        def save():
            new_name = name_var.get().strip()
            
            if not new_name:
                messagebox.showwarning("Invalid Input", "Model name is required")
                return
            
            if new_name != model_name and new_name in model_oids:
                messagebox.showwarning("Duplicate", "Model already exists")
                return
            
            # Update model_oids
            model_oids[new_name] = model_oids[model_name]
            if new_name != model_name:
                del model_oids[model_name]
            
            # Update listbox
            selection = model_list.curselection()
            if selection:
                model_list.delete(selection[0])
                model_list.insert(selection[0], new_name)
                model_list.selection_set(selection[0])
            
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        name_entry.focus()
        name_entry.select_range(0, tk.END)

    def open_ip_manager(self):
        """Open dialog to manage IP addresses"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage IP Addresses")
        dialog.geometry("700x800")
        
        scanning = [False]
        stop_scan = [False]
        
        def on_dialog_close():
            if scanning[0]:
                stop_scan[0] = True
                dialog.after(100, dialog.destroy)
            else:
                dialog.destroy()
        
        dialog.protocol("WM_DELETE_WINDOW", on_dialog_close)
        
        # Load current IP addresses
        try:
            with open("IPS.txt", "r") as f:
                ip_lines = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            ip_lines = []
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IP addresses: {e}")
            dialog.destroy()
            return
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Label
        ttk.Label(main_frame, text="IP Addresses to Monitor", 
                 font=("Helvetica", 12, "bold")).pack(pady=(0, 10))
        
        # Treeview for IPs
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("IP Address",)
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=400)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate tree with existing IPs
        for ip in ip_lines:
            tree.insert("", tk.END, values=(ip,))
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def add_ip():
            self.edit_ip_dialog(dialog, tree)
        
        def edit_ip():
            selection = tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an IP address to edit")
                return
            item = tree.item(selection[0])
            self.edit_ip_dialog(dialog, tree, item['values'][0])
        
        def delete_ip():
            selection = tree.selection()
            if not selection:
                messagebox.showwarning("Selection", "Please select an IP address to delete")
                return
            if messagebox.askyesno("Confirm", "Delete selected IP address?"):
                tree.delete(selection[0])
                try:
                    with open("IPS.txt", "w") as f:
                        for item in tree.get_children():
                            values = tree.item(item)['values']
                            f.write(values[0] + "\n")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save IP addresses: {e}")
        
        ttk.Button(button_frame, text="Add IP", command=add_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit IP", command=edit_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete IP", command=delete_ip).pack(side=tk.LEFT, padx=5)
        
        # Import/Export buttons
        io_frame = ttk.Frame(main_frame)
        io_frame.pack(fill=tk.X, pady=(5, 0))
        
        def import_ips():
            file_path = filedialog.askopenfilename(
                title="Import IP Addresses",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, "r") as f:
                        new_ips = [line.strip() for line in f.readlines() if line.strip()]
                    
                    for ip in new_ips:
                        tree.insert("", tk.END, values=(ip,))
                    
                    messagebox.showinfo("Success", f"Imported {len(new_ips)} IP addresses")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to import IP addresses: {e}")
        
        def export_ips():
            file_path = filedialog.asksaveasfilename(
                title="Export IP Addresses",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, "w") as f:
                        for item in tree.get_children():
                            values = tree.item(item)['values']
                            f.write(values[0] + "\n")
                    
                    messagebox.showinfo("Success", f"Exported IP addresses to {file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export IP addresses: {e}")
        
        ttk.Button(io_frame, text="Import IPs", command=import_ips).pack(side=tk.LEFT, padx=5)
        ttk.Button(io_frame, text="Export IPs", command=export_ips).pack(side=tk.LEFT, padx=5)
        
        # IP Range Scanner
        scan_frame = ttk.LabelFrame(main_frame, text="Scan Subnet for Printers", padding="10")
        scan_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(scan_frame, text="IP Range:").grid(row=0, column=0, padx=5, sticky=tk.W)
        ip_range_var = tk.StringVar()
        ip_range_entry = ttk.Entry(scan_frame, textvariable=ip_range_var, width=25)
        ip_range_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        ttk.Label(scan_frame, text="(e.g., 192.168.1.1-254 or 192.168.1.0/24)").grid(row=0, column=2, padx=5, sticky=tk.W)
        
        scan_progress_var = tk.StringVar(value="")
        scan_progress_label = ttk.Label(scan_frame, textvariable=scan_progress_var, font=("Helvetica", 9))
        scan_progress_label.grid(row=1, column=0, columnspan=3, pady=(5, 0), sticky=tk.W)
        
        log_text = scrolledtext.ScrolledText(scan_frame, height=6, width=60, state=tk.DISABLED)
        log_text.grid(row=2, column=0, columnspan=3, pady=(5, 0))
        
        def scan_log(msg):
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, msg + "\n")
            log_text.see(tk.END)
            log_text.config(state=tk.DISABLED)
        
        scanning = [False]
        stop_scan = [False]
        
        def do_scan():
            ip_range = ip_range_var.get().strip()
            if not ip_range:
                messagebox.showwarning("Input Required", "Please enter an IP range")
                return
            
            ips = parse_ip_range(ip_range)
            if not ips:
                messagebox.showerror("Invalid Range", "Could not parse IP range. Use format: 192.168.1.1-254 or 192.168.1.0/24")
                return
            
            scanning[0] = True
            stop_scan[0] = False
            scan_btn.config(state=tk.DISABLED)
            stop_btn.config(state=tk.NORMAL)
            
            existing_ips = set()
            for item in tree.get_children():
                existing_ips.add(tree.item(item)['values'][0])
            
            found_printers = []
            total = len(ips)
            
            def log_msg(msg):
                dialog.after(0, lambda: scan_log(msg))
            
            def update_progress(cur):
                dialog.after(0, lambda: scan_progress_var.set(f"Scanning {cur}/{total}..."))
            
            def add_printer_to_tree(ip):
                dialog.after(0, lambda: tree.insert("", tk.END, values=(ip,)))
            
            async def scan_one_ip(ip, index):
                for port in PRINTER_PORTS:
                    if stop_scan[0]:
                        return None
                    if await check_port(ip, port):
                        log_msg(f"  ✓ Port {port} open on {ip}")
                        return ip
                
                if await check_snmp_printer(ip):
                    log_msg(f"  ✓ SNMP printer response on {ip}")
                    return ip
                
                return None
            
            async def run_scan():
                found_count = 0
                
                for i, ip in enumerate(ips):
                    if stop_scan[0]:
                        break
                    
                    update_progress(i + 1)
                    log_msg(f"Checking {ip}...")
                    
                    result = await scan_one_ip(ip, i)
                    
                    if result:
                        found_printers.append(result)
                        found_count += 1
                        
                        if ip not in existing_ips:
                            add_printer_to_tree(ip)
                            existing_ips.add(ip)
                            log_msg(f"  🎉 Added: {ip}")
                        else:
                            log_msg(f"  Already exists: {ip}")
                
                dialog.after(0, lambda: scan_progress_var.set(f"Scan complete! Found {len(found_printers)} printers."))
                dialog.after(0, lambda: scan_btn.config(state=tk.NORMAL))
                dialog.after(0, lambda: stop_btn.config(state=tk.DISABLED))
                scanning[0] = False
            
            def run_in_thread():
                asyncio.run(run_scan())
            
            scan_log(f"Starting scan of {len(ips)} IPs...")
            Thread(target=run_in_thread, daemon=True).start()
            
            def stop_scan_func():
                stop_scan[0] = True
                scan_log("Stopping scan...")
            
            stop_btn.config(command=stop_scan_func)
        
        scan_btn = ttk.Button(scan_frame, text="Scan Network", command=do_scan)
        scan_btn.grid(row=0, column=3, padx=10)
        
        stop_btn = ttk.Button(scan_frame, text="Stop", state=tk.DISABLED, command=lambda: None)
        stop_btn.grid(row=0, column=4, padx=5)
        
        # Save/Cancel buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        def save_ips():
            try:
                ips_to_save = []
                for item in tree.get_children():
                    values = tree.item(item)['values']
                    ips_to_save.append(values[0])
                
                with open("IPS.txt", "w") as f:
                    for ip in ips_to_save:
                        f.write(ip + "\n")
                
                self.log(f"✅ Saved {len(ips_to_save)} IP addresses")
                self.load_ips()  # Reload IP count
                messagebox.showinfo("Success", f"Saved {len(ips_to_save)} IP addresses!")
                on_dialog_close()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save IP addresses: {e}")
        
        ttk.Button(btn_frame, text="Save Changes", command=save_ips).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=on_dialog_close).pack(side=tk.RIGHT, padx=5)

    def edit_ip_dialog(self, parent_dialog, tree, existing_ip=None):
        """Dialog for adding/editing IP addresses"""
        dialog = tk.Toplevel(parent_dialog)
        dialog.title("Edit IP Address" if existing_ip else "Add IP Address")
        dialog.geometry("350x150")
        dialog.transient(parent_dialog)
        dialog.grab_set()
        
        # IP field
        ttk.Label(dialog, text="IP Address:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        ip_var = tk.StringVar(value=existing_ip if existing_ip else "")
        ip_entry = ttk.Entry(dialog, textvariable=ip_var, width=30)
        ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Validate IP function
        def validate_ip(ip):
            import re
            pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(pattern, ip):
                return False
            
            parts = ip.split('.')
            for part in parts:
                if int(part) > 255:
                    return False
            return True
        
        # Buttons
        def save():
            ip = ip_var.get().strip()
            
            if not ip:
                messagebox.showwarning("Invalid Input", "IP address is required")
                return
            
            if not validate_ip(ip):
                messagebox.showwarning("Invalid Input", "Please enter a valid IP address (e.g., 192.168.1.1)")
                return
            
            # Check for duplicates
            for item in tree.get_children():
                values = tree.item(item)['values']
                if values[0] == ip and (not existing_ip or values[0] != existing_ip):
                    messagebox.showwarning("Duplicate", "This IP address already exists")
                    return
            
            if existing_ip:
                # Update existing item
                selection = tree.selection()
                if selection:
                    tree.item(selection[0], values=(ip,))
            else:
                # Add new item
                tree.insert("", tk.END, values=(ip,))
            
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Focus on IP field
        ip_entry.focus()
        if existing_ip:
            ip_entry.select_range(0, tk.END)

    def browse_db(self):
        file_path = filedialog.askopenfilename(
            title="Select Database File",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )
        if file_path:
            self.db_path_var.set(file_path)

    def change_db(self):
        new_db = self.db_path_var.get().strip()
        if not new_db:
            messagebox.showwarning("Warning", "Database path cannot be empty!")
            return

        global DB_FILE
        DB_FILE = new_db

        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)
            data["DB_FILE"] = DB_FILE
            with open(OID_FILE, "w") as f:
                json.dump(data, f, indent=4)

            messagebox.showinfo("Success", f"Database path updated to:\n{DB_FILE}")
            self.log(f"✅ Database path updated to {DB_FILE}")
            init_db(DB_FILE)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update DB path: {e}")
            self.log(f"❌ Failed to update DB path: {e}")

    def create_new_db(self):
        # Always use PrinterSupplies.db - cannot be changed
        file_path = filedialog.asksaveasfilename(
            title="Create New Database File",
            initialfile="PrinterSupplies.db",
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )

        if not file_path:
            return

        # Force the filename to be PrinterSupplies.db regardless of user input
        import os
        dir_path = os.path.dirname(file_path)
        forced_path = os.path.join(dir_path, "PrinterSupplies.db")

        try:
            global DB_FILE
            new_db_path = init_db(forced_path)
            self.db_path_var.set(new_db_path)
            DB_FILE = new_db_path

            with open(OID_FILE, "r") as f:
                data = json.load(f)
            data["DB_FILE"] = new_db_path
            with open(OID_FILE, "w") as f:
                json.dump(data, f, indent=4)

            messagebox.showinfo("Success", f"New database created at:\n{new_db_path}")
            self.log(f"✅ New database created at {new_db_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create database: {e}")
            self.log(f"❌ Failed to create database: {e}")

    def browse_printers_db(self):
        file_path = filedialog.askopenfilename(
            title="Select Printers Database File",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )
        if file_path:
            self.printers_db_path_var.set(file_path)

    def change_printers_db(self):
        new_printers_db = self.printers_db_path_var.get().strip()
        if not new_printers_db:
            messagebox.showwarning("Warning", "Printers database path cannot be empty!")
            return

        global DB_PRINTERS
        DB_PRINTERS = new_printers_db

        try:
            with open(OID_FILE, "r") as f:
                data = json.load(f)
            data["DB_PRINTERS"] = DB_PRINTERS
            with open(OID_FILE, "w") as f:
                json.dump(data, f, indent=4)

            messagebox.showinfo("Success", f"Printers database path updated to:\n{DB_PRINTERS}")
            self.log(f"✅ Printers database path updated to {DB_PRINTERS}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update printers DB path: {e}")
            self.log(f"❌ Failed to update printers DB path: {e}")

    def force_cleanup_history(self):
        """Force cleanup of supply history records older than 180 days"""
        current_db = self.get_db_path()
        try:
            deleted = force_cleanup_supply_history(current_db)
            self.log(f"🧹 Force cleanup complete: removed {deleted} records")
            messagebox.showinfo("Cleanup Complete", f"Removed {deleted} records older than 180 days")
        except Exception as e:
            error_msg = f"Cleanup failed: {e}"
            self.log(f"❌ {error_msg}")
            messagebox.showerror("Cleanup Error", error_msg)

    def load_ips(self):
        try:
            with open("ips.txt") as f:
                self.ips = [line.strip() for line in f if line.strip()]
            self.ip_count_var.set(f"IPs loaded: {len(self.ips)}")
            self.log(f"✅ Loaded {len(self.ips)} IP addresses")
        except FileNotFoundError:
            self.ips = []
            self.ip_count_var.set("IPs loaded: 0")
            messagebox.showerror("Error", "ips.txt file not found!")
            self.log("❌ Error: ips.txt file not found!")

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def validate_backup_time(self, time_str):
        """Validate HH:MM format for backup time"""
        try:
            hours, minutes = time_str.split(":")
            hours = int(hours)
            minutes = int(minutes)
            if 0 <= hours <= 23 and 0 <= minutes <= 59:
                return True
            return False
        except (ValueError, AttributeError):
            return False

    def calculate_seconds_until_backup_time(self, backup_time_str):
        """Calculate seconds until the next backup time"""
        try:
            backup_hour, backup_minute = map(int, backup_time_str.split(":"))
            now = datetime.now()
            
            # Create today's backup time
            backup_datetime = now.replace(hour=backup_hour, minute=backup_minute, second=0, microsecond=0)
            
            # If today's backup time has passed, schedule for tomorrow
            if backup_datetime <= now:
                backup_datetime += timedelta(days=1)
            
            return int((backup_datetime - now).total_seconds())
        except (ValueError, AttributeError):
            # Fallback to 24 hours if parsing fails
            return 24 * 3600

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def manual_scan(self):
        if self.auto_scanning or self.manual_scan_active:
            messagebox.showwarning("Warning", "A scan is already running!")
            return

        if not self.ips:
            messagebox.showwarning("Warning", "No IPs loaded!")
            return

        self.log("\n" + "=" * 60)
        self.log("🔍 Starting manual scan...")
        self.status_var.set("Scanning...")
        self.manual_scan_active = True
        self.manual_button.config(state=tk.DISABLED)

        thread = Thread(target=self.run_scan_sync, daemon=True)
        thread.start()

    def start_scanning(self):
        if self.auto_scanning:
            return

        try:
            interval_hours = float(self.interval_var.get())
            if interval_hours < 0.1:
                messagebox.showwarning("Warning", "Interval must be at least 0.1 hours!")
                return
        except ValueError:
            messagebox.showwarning("Warning", "Invalid interval value!")
            return

        # Check if specific time is enabled
        use_specific_time = self.enable_specific_time_var.get()
        backup_time = None
        
        if use_specific_time:
            # Combine hour and minute into backup_time format
            backup_time = f"{self.backup_hour_var.get().zfill(2)}:{self.backup_minute_var.get().zfill(2)}"
            if not self.validate_backup_time(backup_time):
                messagebox.showwarning("Warning", "Invalid backup time format! Use HH:MM format (e.g., 08:00)")
                return

        interval_seconds = int(interval_hours * 3600)

        self.auto_scanning = True
        self.stop_requested = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.manual_button.config(state=tk.DISABLED)

        self.log("\n" + "=" * 60)
        if use_specific_time:
            self.log(f"▶ Auto-scan started (interval: {interval_hours} hours, starts at: {backup_time})")
        else:
            self.log(f"▶ Auto-scan started (interval: {interval_hours} hours only)")
        
        # Restart email scheduler when scanning starts
        self.stop_email_scheduler()
        self.start_email_scheduler()

        thread = Thread(target=self.run_auto_scan, args=(interval_seconds, backup_time), daemon=True)
        thread.start()

    def stop_scanning(self):
        self.auto_scanning = False
        self.stop_requested = True
        self.status_var.set("Stopping...")
        self.log("⏹ Stop requested, waiting for current operation to complete...")
        # Also stop email scheduler when stopping scans
        self.stop_email_scheduler()

    def _finalize_stop(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.manual_button.config(state=tk.NORMAL)
        self.status_var.set("Stopped")
        self.log("✅ Auto-scan stopped")

    def run_scan_sync(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.perform_scan(is_manual=True))
            loop.close()
        except Exception as e:
            self.log(f"❌ Error during scan: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.manual_scan_active = False
            self.root.after(0, lambda: self.manual_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set("Ready"))

    def run_auto_scan(self, interval, backup_time):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Calculate initial wait time until backup time (if specified)
            wait_until_backup = 0
            if backup_time:
                wait_until_backup = self.calculate_seconds_until_backup_time(backup_time)
            
            while self.auto_scanning and not self.stop_requested:
                # Set initial timer based on whether it's first scan or subsequent
                current_interval = wait_until_backup if wait_until_backup > 0 else interval
                
                # Start countdown immediately for consistent intervals
                remaining = current_interval
                while remaining > 0 and self.auto_scanning and not self.stop_requested:
                    hours = remaining // 3600
                    minutes = (remaining % 3600) // 60
                    seconds = remaining % 60

                    if hours > 0:
                        time_str = f"{hours}h {minutes}m {seconds}s"
                    elif minutes > 0:
                        time_str = f"{minutes}m {seconds}s"
                    else:
                        time_str = f"{seconds}s"

                    if wait_until_backup > 0 and backup_time:
                        status_msg = f"Next scan in {time_str} (at {backup_time})"
                    else:
                        status_msg = f"Next scan in {time_str}"
                    self.root.after(0, lambda msg=status_msg: self.status_var.set(msg))
                    loop.run_until_complete(asyncio.sleep(1))
                    remaining -= 1
                
                # Reset wait time for subsequent scans
                wait_until_backup = 0

                if not self.auto_scanning or self.stop_requested:
                    break

                # Perform the scan
                try:
                    loop.run_until_complete(self.perform_scan(is_manual=False))
                except Exception as e:
                    self.log(f"❌ Error during scan: {e}")
                    import traceback
                    self.log(traceback.format_exc())

                if not self.auto_scanning or self.stop_requested:
                    break
        finally:
            loop.close()
            self.root.after(0, self._finalize_stop)

    async def perform_scan(self, is_manual=False):
        """
        Scan all printers, log results, and send a single email for all alerts at the end.
        """
        current_db = self.get_db_path()
        deleted = cleanup_supply_history(current_db)
        if deleted:
            self.root.after(
                0,
                lambda d=deleted: self.log(
                    f"🧹 History cleanup: removed {d} old records"
                )
            )

        self.root.after(0, lambda: self.log("\n" + "-" * 60))
        self.root.after(0, lambda: self.log(f"🕐 Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))

        if not self.ips:
            self.root.after(0, lambda: self.log("❌ No IPs to scan!"))
            return

        all_alerts = []

        for idx, ip in enumerate(self.ips, 1):
            if not is_manual and (not self.auto_scanning or self.stop_requested):
                self.root.after(0, lambda: self.log("⏹ Scan interrupted by user"))
                break

            self.root.after(0, lambda i=ip, n=idx: self.log(f"\n[{n}/{len(self.ips)}] Processing {i}..."))

            try:
                result, alerts = await scan_printer(
                    ip,
                    lambda msg: self.root.after(0, lambda m=msg: self.log(m)),
                    db_path=current_db
                )
                if alerts:
                    all_alerts.extend(alerts)

                if not result:
                    self.root.after(0, lambda i=ip: self.log(f"  ⚠️ No data returned for {i}"))

            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.root.after(0, lambda e=e, i=ip: self.log(f"❌ Error scanning {i}: {str(e)}"))
                self.root.after(0, lambda t=tb: self.log(t))

            if not is_manual and (not self.auto_scanning or self.stop_requested):
                self.root.after(0, lambda: self.log("⏹ Scan interrupted by user"))
                break

        # Send email based on schedule configuration (only if alerts are enabled)
        if ALERT_CONFIG.get("enabled", False):
            html_body = generate_html_alert(all_alerts)
            subject = "⚠️ Printer Supply Alert" if all_alerts else "✅ Printer Supplies OK"
            
            # Per-scan email mode (only when scheduling is disabled)
            if not EMAIL_CONFIG.get("schedule_enabled", False):
                send_email_alert(subject, html_body, html=True)
                email_status = f"📨 Email alert sent ({'ALERTS' if all_alerts else 'All OK'})"
            else:
                # Scheduled emails handled by dedicated email scheduler thread
                email_status = "📧 Scheduled email mode - handled by scheduler thread"
            
            self.root.after(0, lambda msg=email_status: self.log(msg))
        else:
            self.root.after(0, lambda: self.log("📧 Email alerts disabled - skipping email send"))

        self.root.after(0, lambda: self.log("-" * 60))
        self.root.after(0, lambda: self.log("✅ Scan completed"))
        self.root.after(0, lambda: self.last_scan_var.set(f"Last scan: {datetime.now().strftime('%H:%M:%S')}"))

        if is_manual or not self.auto_scanning:
            self.root.after(0, lambda: self.status_var.set("Ready"))

    def start_email_scheduler(self):
        """Start the email scheduler thread if scheduling is enabled"""
        if EMAIL_CONFIG.get("schedule_enabled", False) and ALERT_CONFIG.get("enabled", False):
            self.email_scheduler_running = True
            thread = Thread(target=self.run_email_scheduler, daemon=True)
            thread.start()
            self.log("📧 Email scheduler started")

    def stop_email_scheduler(self):
        """Stop the email scheduler"""
        self.email_scheduler_running = False
        self.log("📧 Email scheduler stopped")

    def run_email_scheduler(self):
        """Run the email scheduler in background thread"""
        while self.email_scheduler_running:
            try:
                if EMAIL_CONFIG.get("schedule_enabled", False) and ALERT_CONFIG.get("enabled", False):
                    if should_send_scheduled_email() and can_send_scheduled_email_today():
                        self.root.after(0, lambda: self.log("📧 Sending scheduled email..."))
                        
                        # Get current printer status for the email
                        all_alerts = self.get_current_alerts()
                        html_body = generate_html_alert(all_alerts)
                        subject = "⚠️ Printer Supply Alert" if all_alerts else "✅ Printer Supplies OK"
                        
                        try:
                            send_email_alert(subject, html_body, html=True)
                            mark_scheduled_email_sent()
                            schedule_time = f"{EMAIL_CONFIG.get('schedule_hour', '9')}:{EMAIL_CONFIG.get('schedule_minute', '0')}"
                            self.root.after(0, lambda: self.log(f"📨 Scheduled email sent at {schedule_time}"))
                        except Exception as e:
                            self.root.after(0, lambda: self.log(f"❌ Failed to send scheduled email: {e}"))
                
                # Sleep for 30 seconds before next check
                for _ in range(30):
                    if not self.email_scheduler_running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌ Email scheduler error: {e}"))
                time.sleep(60)  # Wait longer on error

    def get_current_alerts(self):
        """Get current alerts from all printers without scanning (uses latest DB data)"""
        alerts = []
        try:
            current_db = self.get_db_path()
            
            if not self.ips:
                return alerts
                
            conn = get_db_connection(current_db)
            c = conn.cursor()
            
            for ip in self.ips:
                # Get latest scan data for this IP
                c.execute("""
                    SELECT model FROM printer_scans 
                    WHERE ip = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                """, (ip,))
                result = c.fetchone()
                
                if not result:
                    continue
                    
                model = result[0]
                
                # Get all data for this printer
                c.execute("PRAGMA table_info(printer_scans)")
                columns = [col[1] for col in c.fetchall()]
                
                c.execute("""
                    SELECT * FROM printer_scans 
                    WHERE ip = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                """, (ip,))
                row = c.fetchone()
                
                if row:
                    printer_data = dict(zip(columns, row))
                    
                    # Database stores columns with "pct" instead of "%" due to sanitize_column_name
                    # Convert data back to format expected by check_supply_alerts
                    converted_data = {}
                    for key, value in printer_data.items():
                        if key.endswith("pct"):
                            # Convert "Black_Toner_pct" back to "Black Toner %"
                            original_key = key.replace("_pct", " %")
                            converted_data[original_key] = value
                        else:
                            converted_data[key] = value
                    
                    # Use converted data for alert checking
                    hostname = printer_data.get('Hostname', 'Unknown Host')
                    printer_alerts = check_supply_alerts(ip, model, converted_data, hostname)
                    alerts.extend(printer_alerts)
                    
            conn.close()
            
        except Exception as e:
            self.root.after(0, lambda: self.log(f"❌ Error getting current alerts: {e}"))
            
        return alerts

    def send_test_email(self):
        if not EMAIL_RECIPIENTS:
            messagebox.showwarning("No Recipients", "No email recipients are configured.")
            return

        def worker():
            try:
                self.root.after(0, lambda: self.log("📨 Sending test email alert..."))
                send_test_email(resource_name="Printer Scanner Test")
                self.root.after(0, lambda: self.log("✅ Test email sent successfully"))
                self.root.after(
                    0,
                    lambda: messagebox.showinfo("Success", "Test email sent successfully!")
                )
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌ Test email failed: {e}"))
                self.root.after(
                    0,
                    lambda: messagebox.showerror("Error", f"Failed to send test email:\n{e}")
                )

        Thread(target=worker, daemon=True).start()


def main():
    root = tk.Tk()
    app = PrinterScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()