# DIMS - Device Inventory Management System

A cross-platform desktop application for monitoring printer supply levels via SNMP. Scans networked printers, tracks toner/drum/imaging unit levels over time, and sends email alerts when supplies are running low.

---

## How It Works

```
┌─────────────────┐     SNMP (UDP 161)     ┌──────────────┐
│  Printer Scanner │ ─────────────────────→ │  Printers    │
│  GUI (Tkinter)   │ ←───────────────────── │  (SNMP OIDs) │
│                  │                        └──────────────┘
│  ┌────────────┐  │
│  │ SQLite DB  │◀─│── Saves scan results, supply history
│  └────────────┘  │
│  ┌────────────┐  │
│  │ SMTP Email │──│── Sends alerts when supplies are low
│  └────────────┘  │
└─────────────────┘
```

The application runs on a schedule (or manually) and performs these steps for each printer IP:

1. **Fetch base OIDs** — Gets hostname, description, serial number, location
2. **Match model** — Uses the printer's description to look up model-specific OIDs
3. **Fetch supply OIDs** — Gets toner/drum/imaging unit current/max values
4. **Calculate percentages** — Converts "current/max" pairs into percentages
5. **Save to database** — Writes to `printer_scans` (latest), `supply_history` (daily snapshots), `supply_changes` (change log)
6. **Check thresholds** — Compares percentages against low/critical alert thresholds
7. **Send email alerts** — Sends an HTML summary via SMTP if thresholds are crossed

---

## Database Schema

The SQLite database (`PrinterSupplies.db`) has four tables:

### `printer_scans`

Stores the **latest** scan data per printer. Columns are dynamically added as new supply types are discovered.

| Column      | Type   | Description                        |
|-------------|--------|------------------------------------|
| `id`        | INTEGER| Primary key, auto-increment        |
| `ip`        | TEXT   | Printer IP address                 |
| `timestamp` | TEXT   | ISO-format scan timestamp          |
| `model`     | TEXT   | Printer model name                 |
| `Hostname`  | TEXT   | *(dynamic)* Hostname from SNMP     |
| `Description` | TEXT | *(dynamic)* Full device description |
| `Serial_Number` | TEXT | *(dynamic)* Serial number        |
| `Black_Toner_pct` | TEXT | *(dynamic)* Remaining %        |
| `Imaging_Unit_pct` | TEXT | *(dynamic)* Remaining %       |
| ...         |        | Additional columns added per OID   |

> Column names are sanitized: spaces → `_`, `%` → `pct` (e.g. `Black Toner %` becomes `Black_Toner_pct`).

### `supply_history`

Daily snapshots of every supply value. One row per IP + supply name + date.

| Column        | Type   | Description                    |
|---------------|--------|--------------------------------|
| `id`          | INTEGER| Primary key                    |
| `ip`          | TEXT   | Printer IP address             |
| `model`       | TEXT   | Printer model                  |
| `supply_name` | TEXT   | Supply name (e.g. Black Toner %) |
| `value`       | TEXT   | Value at time of scan          |
| `scan_date`   | TEXT   | Date in YYYY-MM-DD format      |
| `timestamp`   | TEXT   | Full ISO timestamp              |

**Unique constraint:** `(ip, supply_name, scan_date)` — only one entry per supply per day.

### `supply_changes`

Logs every detected change between scans.

| Column        | Type   | Description                    |
|---------------|--------|--------------------------------|
| `id`          | INTEGER| Primary key                    |
| `ip`          | TEXT   | Printer IP address             |
| `model`       | TEXT   | Printer model                  |
| `supply_name` | TEXT   | Supply name                    |
| `old_value`   | TEXT   | Previous scan value            |
| `new_value`   | TEXT   | Current scan value             |
| `timestamp`   | TEXT   | When the change was detected   |

### `printer_maintenance`

Auto-generated maintenance records when supplies are consumed significantly (>5% drop).

| Column            | Type   | Description                       |
|-------------------|--------|-----------------------------------|
| `id`              | INTEGER| Primary key                       |
| `printer_id`      | INTEGER| FK to printer_scans.id            |
| `maintenance_type`| TEXT   | e.g. `SUPPLY_CONSUMPTION`         |
| `description`     | TEXT   | e.g. "Black Toner: 75% → 45%"    |
| `reported_issue`  | TEXT   | Detailed description              |
| `start_time`      | TEXT   | When the drop was detected        |
| `end_time`        | TEXT   | *(nullable)*                      |
| `technician`      | TEXT   | "System Auto-Detection"           |
| `status`          | TEXT   | Defaults to `COMPLETED`           |
| `cost`            | REAL   | *(nullable)*                      |
| `parts_used`      | TEXT   | *(nullable)*                      |
| `next_due_date`   | TEXT   | *(nullable)*                      |
| `created_at`      | TEXT   | Creation timestamp                |
| `updated_at`      | TEXT   | Last update timestamp             |

---

## Data Flow

### Scan Lifecycle

```
User clicks "Scan Now" or auto-scan timer fires
        │
        ▼
cleanup_supply_history()          ← Deletes old data per retention policy
        │
        ▼
For each IP in IPS.txt:
    │
    ├─ fetch_oids(ip, BASE_OIDS)  ← SNMP: hostname, description, serial, location
    │
    ├─ Match printer model
    │   from description string
    │
    ├─ fetch_oids(ip, model_oids) ← SNMP: toner/drum/imaging unit values
    │
    ├─ compute_percent()          ← Convert Current/Max pairs to percentages
    │
    ├─ save_scan()                ← UPSERT into printer_scans table
    │   └─ log_supply_change()    ← INSERT into supply_changes if values changed
    │   └─ create_supply_maintenance_record() ← If >5% drop detected
    │
    ├─ save_supply_history()      ← INSERT/UPDATE supply_history (daily snapshot)
    │
    └─ check_supply_alerts()      ← Compare % values against thresholds
        │
        ▼
generate_html_alert()             ← Build HTML email body
        │
        ▼
send_email_alert()                ← Send via SMTP (if alerts enabled)
```

### Database Read Path (Scheduled Emails)

When email scheduling is enabled, the app reads the latest data from `printer_scans` to build status emails — without performing a fresh SNMP scan:

```
run_email_scheduler()
    │
    ▼
should_send_scheduled_email()     ← Check if it's time to send
can_send_scheduled_email_today()  ← Check if already sent today
    │
    ▼
get_current_alerts()
    │
    ├─ SELECT latest printer_scans row per IP
    ├─ Convert pct column names back to % format
    ├─ Run check_supply_alerts() on the data
    │
    ▼
generate_html_alert() → send_email_alert()
mark_scheduled_email_sent()       ← Save timestamp to oids.json
```

---

## OID System

The application uses SNMP OIDs to query printer data. All OIDs are defined in `oids.json`.

### Base OIDs (all printers)

| Name           | OID                          | Description         |
|----------------|------------------------------|---------------------|
| Hostname       | `.1.3.6.1.2.1.1.5.0`        | Device hostname     |
| Description    | `.1.3.6.1.2.1.1.1.0`        | Full model string   |
| Location       | `.1.3.6.1.2.1.1.6.0`        | Physical location   |
| Serial Number  | `.1.3.6.1.2.1.43.5.1.1.17.1`| Serial number       |

### Model-Specific OIDs

Each printer model has its own set of supply OIDs. The system matches the printer's description against model names in `oids.json`.

**Naming convention:**
- `{Name} Current` — Current value (e.g. `Black Toner Current`)
- `{Name} Max` — Maximum value (e.g. `Black Toner Max`)
- The system automatically computes `{Name} %` from the pair

If no model-specific match is found, the `GENERIC` profile is used as fallback.

### Managing OIDs

Use the **Manage OIDs** button in the GUI or edit `oids.json` directly. The OID manager supports:
- Adding/editing/deleting base OIDs
- Adding/editing/deleting printer model profiles
- Copying OIDs from existing models when creating new ones

---

## Email Alert System

### Configuration

Email settings are stored in `oids.json` under `EMAIL_CONFIG`:

| Field             | Description                     | Default            |
|-------------------|---------------------------------|--------------------|
| `smtp_server`     | SMTP server address             | `smtp.gmail.com`   |
| `smtp_port`       | SMTP port (TLS)                 | `587`              |
| `username`        | SMTP auth username              |                    |
| `password`        | SMTP auth password              |                    |
| `from_address`    | From header                     |                    |
| `schedule_enabled`| Use daily schedule vs per-scan  | `false`            |
| `schedule_hour`   | Hour for daily email            | `00`               |
| `schedule_minute` | Minute for daily email          | `53`               |

### Alert Thresholds

| Field                | Description                               | Default |
|----------------------|-------------------------------------------|---------|
| `low_threshold`      | Supply % below this triggers LOW alert    | `25`    |
| `critical_threshold` | Supply % below this triggers CRITICAL     | `10`    |
| `monitored_supplies` | List of supplies to monitor (empty = all) | `[]`    |

### Email Modes

1. **Per-scan mode** — An email is sent after every scan cycle (with or without alerts)
2. **Scheduled mode** — A single daily email is sent at the configured time, with data from the latest scan

The HTML email groups alerts by printer and color-codes them as LOW (yellow) or CRITICAL (red).

---

## Subnet Scanner (Printer Discovery)

The IP Manager includes a built-in subnet scanner that can discover printers on your network. It works by:

1. **Parsing IP ranges** — Supports `192.168.1.1-254` and `192.168.1.0/24` formats
2. **Port scanning** — Checks common printer ports: 9100 (raw), 515 (LPD), 631 (IPP)
3. **SNMP probe** — Queries the printer MIB OID `.1.3.6.1.2.1.25.3.5.1.1.1`

Found printers can be added directly to the monitoring list.

---

## Data Retention & Cleanup

The supply history is automatically pruned after each scan:

| Age            | Policy                           |
|----------------|----------------------------------|
| < 90 days      | Keep all daily data              |
| 90–180 days    | Keep only first + last entry per month |
| > 180 days     | Delete entirely                  |

A **Force Cleanup** button is available to immediately delete all records older than 180 days.

---

## Configuration Files

| File                | Purpose                                         |
|---------------------|-------------------------------------------------|
| `oids.json`         | OID definitions, database paths, email config, alert thresholds, scan settings |
| `IPS.txt`           | One IP address per line — the printers to scan  |
| `PrinterSupplies.db`| SQLite database with all scan data and history  |
| `Printers.db`       | Optional secondary database for hostname records|

### `oids.json` Structure

```json
{
  "BASE_OIDS": { ... },
  "MODELS": { "GENERIC": {...}, "Xerox VersaLink B405": {...} },
  "DB_FILE": "PrinterSupplies.db",
  "DB_PRINTERS": "Printers.db",
  "EMAIL_CONFIG": { ... },
  "EMAIL_RECIPIENTS": [...],
  "ALERT_CONFIG": { ... },
  "SCAN_CONFIG": {
    "interval": 1.0,
    "backup_time": "18:00",
    "auto_scan_enabled": false,
    "enable_specific_time": false
  },
  "last_email_sent": "2026-02-07T00:53:02.770974"
}
```

---

## Dependencies

- Python 3.9+
- `pysnmp` — SNMP communication
- `tkinter` — GUI (included with Python)
- Standard library: `sqlite3`, `smtplib`, `asyncio`, `json`, `re`, `threading`, `socket`

Install with:

```bash
pip install pysnmp
```

---

## Quick Start

1. Install Python 3.9+ and the `pysnmp` package
2. Edit `IPS.txt` with the IP addresses of your printers (one per line)
3. Configure `oids.json` with your printer models and email settings (or use the GUI)
4. Run:

```bash
python PrinterScannerGUI.py
```

### Building an Executable

A PyInstaller spec file is included:

```bash
pip install pyinstaller
pyinstaller PrinterSupplyScanner.spec
```

---

## Architecture Notes

- **Single-file application** — The entire application is in `PrinterScannerGUI.py` (~3000 lines)
- **Async SNMP** — All SNMP queries use `asyncio` via `pysnmp.hlapi.v3arch.asyncio` for non-blocking I/O
- **Threading model** — GUI runs on the main thread; scans and email schedulers run on daemon threads
- **Thread-safe UI updates** — All GUI updates from background threads use `root.after(0, ...)` to schedule work on the main thread
- **WAL mode** — SQLite connections use Write-Ahead Logging (`PRAGMA journal_mode=WAL`) for concurrent access
- **Self-healing DB** — If the configured database path fails, a fallback is created next to the script
