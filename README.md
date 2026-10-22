# 🛡️ CyberShield — Suspicious Login Detector

A beginner-friendly cybersecurity portfolio project built with Python and Streamlit.
CyberShield analyses login records and flags IP addresses that show signs of a
**brute-force attack** — repeated failed login attempts from the same source.

> ⚠️ **This is a student demonstration project.**
> All data is simulated. CyberShield is **not** a production intrusion-detection system
> and does not connect to any real network or authentication service.

---

## Features

| Feature | Description |
|---|---|
| **KPI dashboard** | Total attempts, successful logins, failed logins, invalid-status rows, suspicious IPs |
| **Suspicious IP detection** | Flags IPs with failed attempts ≥ configurable threshold (default: 5) |
| **Risk classification** | 🔴 Critical / 🟠 High / 🟡 Medium labels based on failed-attempt count |
| **Detection reasons** | Explains why each IP was flagged (failed count, multiple usernames, success-after-failures) |
| **Time-window filter** | Optionally restrict detection to the last 1 / 6 / 12 / 24 / 48 hours |
| **Status & suspicious-only filters** | Filter raw records by login status or suspicious IPs only |
| **CSV upload** | Upload your own login logs; full validation with clear error/warning messages |
| **Upload preview** | See accepted row count, warnings, and a 10-row preview after upload |
| **Comparison chart** | Side-by-side successful vs failed login bar chart |
| **Failed-count chart** | Per-IP failed login bar chart |
| **Downloadable report** | CSV security report with summary metrics + per-IP detail |
| **Duplicate detection** | Exact duplicate rows are removed from uploaded files |

---

## Technology Stack

| Tool | Purpose |
|---|---|
| Python 3.9+ | Core language |
| Streamlit | Web dashboard |
| pandas | Data loading, filtering, aggregation |
| pytest | Automated testing |

---

## Project Structure

```
CyberShield/
├── app.py                  # Streamlit dashboard
├── detector.py             # All detection and data-processing logic (no UI)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── .gitignore
├── data/
│   ├── login_records.csv   # Built-in 44-record sample dataset
│   └── test_upload.csv     # Small CSV used for testing the upload feature
└── tests/
    ├── __init__.py
    └── test_detector.py    # Automated tests (pytest)
```

---

## CSV Schema

Your CSV file must contain these four columns (header names are case-insensitive):

| Column | Type | Description | Example |
|---|---|---|---|
| `timestamp` | datetime | When the login attempt occurred | `2024-01-15 08:01:12` |
| `ip_address` | string | IP address of the login attempt | `192.168.1.10` |
| `username` | string | Username that was attempted | `alice` |
| `status` | string | Outcome — must be `success` or `failed` | `failed` |

**Validation rules applied on upload:**
- Missing required columns → rejected with a clear error message
- Entirely blank rows → removed (warning shown)
- Exact duplicate rows → removed (warning shown)
- Invalid status values (not `success`/`failed`) → rows removed (warning shown)
- Rows missing any required field → removed (warning shown)
- Unparseable timestamps → kept as NaT (warning shown)
- Extra columns → silently ignored

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/cybershield.git
cd cybershield
```

### 2. Create a virtual environment (Windows)

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

---

## Running the App

```powershell
python -m streamlit run app.py
```

Streamlit will open your browser automatically at `http://localhost:8501`.

---

## Running the Tests

```powershell
python -m pytest tests/ -v
```

Expected output: all tests pass. The test suite covers:

- `get_failed_attempts` — correct counts, empty inputs, sum reconciliation
- `get_suspicious_ips` — exactly-at-threshold, one-below, above, multiple IPs, threshold changes
- `summarise_statuses` — count totals, invalid detection, empty DataFrames
- `validate_and_parse_upload` — empty files, missing columns, bad status, duplicates, NaT timestamps, malformed CSV
- `risk_label` — every risk band
- `get_detection_reasons` — failed count, multi-username, success-after-failures
- `filter_by_time_window` — no filter, 1-hour window, NaT exclusion
- `build_report_df` — required columns, summary metric reconciliation, no-suspicious-IP case, CSV encoding

---

## How to Interpret Results

### KPI Cards
- **Total Attempts** — all rows in the active dataset
- **Successful / Failed** — rows with `status = success` or `status = failed`
- **Invalid Status** — rows that are neither success nor failed (excluded from detection)
- **Suspicious IPs** — IPs that meet the failed-attempts threshold

### Risk Levels (heuristics only)

| Label | Failed Attempts | Meaning |
|---|---|---|
| 🔴 Critical | 10+ | Very high volume of failures — strong brute-force signal |
| 🟠 High | 7–9 | High volume, warrants investigation |
| 🟡 Medium | 5–6 | Meets threshold; may be mistyped passwords or light probing |

> Risk labels do **not** prove malicious intent. They are relative indicators
> within the dataset for learning purposes only.

### Detection Reasons

Each flagged IP shows one or more detection reasons:

| Reason | What it means |
|---|---|
| `N failed attempts (≥T threshold)` | Basic threshold rule triggered |
| `Targeted N different username(s)` | Possible credential-stuffing or account enumeration |
| `Successful login after repeated failures` | Failures followed by a success — possible break-in |

### The Sample Dataset

The built-in [`data/login_records.csv`](data/login_records.csv) contains **44 simulated
login events** (7 successful, 37 failed) across 8 IP addresses. At the default threshold
of 5, five IPs are flagged as suspicious.

**Historical note:** Earlier project notes referenced 9 successful / 35 failed logins.
After inspection of the actual CSV, the correct counts are 7 / 37. The earlier figures
came from a draft version of the dataset that no longer exists.

---

## Limitations

- **Simulated data only.** No real users, IPs, or login systems are involved.
- **No persistence.** Results are not saved between sessions.
- **No real-time monitoring.** The app analyses static CSV snapshots, not live streams.
- **No IP geolocation or WHOIS lookup.**
- **No automatic blocking.** CyberShield never modifies any external system.
- **Threshold-based detection only.** It does not use machine learning or anomaly detection.
- **IPv4 only** in the sample data; IPv6 addresses would work but are untested.

---

## Screenshots

*(Add screenshots here once the app is running)*

| View | Screenshot |
|---|---|
| Dashboard overview | `screenshots/overview.png` |
| Suspicious IP table | `screenshots/suspicious_ips.png` |
| Downloaded report | `screenshots/report_csv.png` |

---

## Ethical Use

This tool is for **educational purposes only**. Do not use it against real systems
or real user data without explicit authorisation. Real brute-force detection should
be handled by dedicated security tools (e.g. fail2ban, SIEM platforms) operated by
qualified security professionals.

---

## License

MIT — free to use and modify for learning and portfolio projects.
