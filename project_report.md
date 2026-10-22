# CyberShield: Suspicious Login Activity Detection System

---

**IBM Cybersecurity Project Submission**

| | |
|---|---|
| **Project Title** | CyberShield: Suspicious Login Activity Detection System |
| **Course** | IBM Cybersecurity |
| **Submission Type** | Practical Portfolio Project |
| **Programming Language** | Python 3.9+ |
| **Framework** | Streamlit |
| **Project Repository** | `c:\Users\parul\Desktop\Cybershield` |

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Project Objectives](#4-project-objectives)
5. [Technologies and Tools Used](#5-technologies-and-tools-used)
6. [System Requirements](#6-system-requirements)
7. [System Architecture and Workflow](#7-system-architecture-and-workflow)
8. [Detailed Features and Functionality](#8-detailed-features-and-functionality)
9. [Implementation Details](#9-implementation-details)
10. [How to Install and Run the Project](#10-how-to-install-and-run-the-project)
11. [Testing and Results](#11-testing-and-results)
12. [Screenshots](#12-screenshots)
13. [Limitations](#13-limitations)
14. [Future Scope](#14-future-scope)
15. [Conclusion](#15-conclusion)
16. [References](#16-references)

---

## 1. Abstract

CyberShield is an educational cybersecurity toolkit built with Python and Streamlit. It provides two main capabilities: a login-activity analyser that detects suspicious IP addresses from CSV login logs, and a website header inspector that checks whether a public URL uses HTTPS and returns common HTTP security response headers.

The login-analysis module loads either a built-in 44-record simulated dataset or a user-uploaded CSV file, counts failed login attempts per IP address, and flags any IP that meets or exceeds a configurable threshold (default: 5). Flagged IPs are enriched with a risk level, a human-readable detection reason, and can be exported as a downloadable CSV report. Dashboard filters allow narrowing the view by time window, login status, and suspicious IPs only.

The URL security module sends a single HTTP GET request to a user-supplied address, inspects six well-known HTTP security response headers grouped into recommended and situational categories, and presents findings with clear explanatory text and an explicit disclaimer about the scope and limitations of the check.

The project includes a 57-test automated test suite covering all detection logic, CSV validation, risk classification, time-window filtering, and report generation. All 57 tests pass.

---

## 2. Introduction

Unauthorised access through credential-based attacks is one of the most common threat vectors in cybersecurity. Attackers frequently attempt to guess or brute-force login credentials by submitting large numbers of failed login attempts against an account or service. Identifying such patterns early is a foundational security monitoring skill.

At the same time, web application security depends significantly on correctly configured HTTP response headers. Headers such as `Strict-Transport-Security`, `Content-Security-Policy`, and `X-Content-Type-Options` help browsers enforce safe behaviour and defend against well-known attacks including protocol downgrade, cross-site scripting, and MIME sniffing.

CyberShield demonstrates both of these concepts in a practical, interactive web application. It is designed to be understandable by learners new to cybersecurity and Python, while also illustrating the kind of threshold-based detection logic used in production tools such as `fail2ban` and `Snort`.

> **Disclaimer:** CyberShield uses entirely simulated login data. It is an educational demonstration project and is not intended as a replacement for professional security tooling or production intrusion detection systems.

---

## 3. Problem Statement

Organisations generate large volumes of authentication log data. Without automated analysis, security teams cannot efficiently identify IP addresses exhibiting brute-force behaviour. Similarly, many websites inadvertently omit important HTTP security headers, leaving users exposed to avoidable risks.

A beginner entering the cybersecurity field needs a practical, hands-on way to:

1. Understand what a brute-force login attack looks like in log data.
2. Apply a rule-based detection algorithm (threshold on failed attempts per IP).
3. Enrich detection results with risk levels and explanatory context.
4. Understand the role of HTTP security headers without being misled by oversimplified scoring systems.

CyberShield addresses all four points through a self-contained, interactive dashboard.

---

## 4. Project Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Load and display login records from a built-in CSV sample | Implemented |
| 2 | Accept user-uploaded CSV files with full validation and error handling | Implemented |
| 3 | Count failed login attempts per IP address | Implemented |
| 4 | Flag IPs with failed attempts ≥ a configurable threshold (default: 5) | Implemented |
| 5 | Classify flagged IPs by risk level (Critical / High / Medium) | Implemented |
| 6 | Explain detection reasons per flagged IP | Implemented |
| 7 | Provide a time-window filter (last 1 / 6 / 12 / 24 / 48 hours) | Implemented |
| 8 | Provide status and suspicious-only filters for the raw records table | Implemented |
| 9 | Generate and allow download of a CSV security report | Implemented |
| 10 | Check a public URL for HTTPS and HTTP security response headers | Implemented |
| 11 | Present header results honestly, with clear scope disclaimers | Implemented |
| 12 | Cover all detection logic with an automated test suite | Implemented (57 tests) |

---

## 5. Technologies and Tools Used

| Technology | Version | Purpose |
|---|---|---|
| **Python** | 3.9+ (tested on 3.13.5) | Core programming language |
| **Streamlit** | ≥ 1.32.0 | Interactive web dashboard framework |
| **pandas** | ≥ 2.0.0 | Data loading, filtering, grouping, aggregation |
| **requests** | ≥ 2.28.0 | HTTP GET requests for URL security checking |
| **pytest** | ≥ 7.4.0 | Automated testing framework |
| **Python `io`** | stdlib | In-memory CSV parsing for file uploads |
| **Python `urllib.parse`** | stdlib | URL scheme normalisation |

No external databases, cloud services, authentication systems, or machine-learning libraries are used.

---

## 6. System Requirements

### Hardware

- Any modern laptop or desktop computer
- Internet connection required only for the URL Security Check tab

### Software

- Python 3.9 or later
- `pip` (Python package manager)
- A modern web browser (Chrome, Firefox, Edge, Safari)

### Python packages (from `requirements.txt`)

```
streamlit>=1.32.0
pandas>=2.0.0
requests>=2.28.0
pytest>=7.4.0
```

---

## 7. System Architecture and Workflow

### File structure

```
CyberShield/
├── app.py                  ← Streamlit dashboard (UI only, no logic)
├── detector.py             ← All login-analysis logic (no UI imports)
├── url_checker.py          ← All URL-checking logic (no UI imports)
├── requirements.txt
├── README.md
├── data/
│   ├── login_records.csv   ← Built-in 44-record simulated dataset
│   └── test_upload.csv     ← Small CSV used during development testing
└── tests/
    ├── __init__.py
    └── test_detector.py    ← 57 automated tests (pytest)
```

### Architecture principle

The project separates concerns into three layers:

```
┌─────────────────────────────────────────┐
│  app.py  — Streamlit UI                  │
│  (renders widgets, calls logic modules)  │
└────────────┬───────────────┬────────────┘
             │               │
    ┌─────────────┐   ┌──────────────┐
    │ detector.py │   │url_checker.py│
    │ (pure Python│   │ (pure Python │
    │  functions) │   │  functions)  │
    └─────────────┘   └──────────────┘
             │
    ┌─────────────────┐
    │data/login_       │
    │records.csv       │
    └─────────────────┘
```

`detector.py` and `url_checker.py` contain zero Streamlit imports. They can be imported and tested independently of the UI.

### Login-analysis workflow

```
User opens browser
    → Streamlit loads app.py
    → Sidebar: user selects data source (built-in or upload), threshold, filters
    → df = load_login_records() OR validate_and_parse_upload()
    → df_filtered = filter_by_time_window(df, hours)
    → stats = summarise_statuses(df_filtered)
    → suspicious = get_suspicious_ips(df_filtered, threshold)
    → All sections render from df_filtered and suspicious
    → User may download cybershield_report.csv
```

### URL-check workflow

```
User enters URL → clicks "Run Security Check"
    → check_url(url) in url_checker.py
    → _normalise_url() adds https:// if scheme missing
    → requests.get() with 10-second timeout
    → HTTPS check on final response URL
    → Six headers inspected, grouped into recommended / situational
    → Result dict returned → app.py renders findings with disclaimer
```

---

## 8. Detailed Features and Functionality

### Tab 1: Login Analysis

#### 8.1 Built-in Sample Dataset

The file `data/login_records.csv` contains **44 simulated login records** from 8 fictional IP addresses, spanning approximately 40 minutes on 2024-01-15. The dataset contains:

- **7 successful** logins
- **37 failed** logins
- **0** invalid status values

All status values are normalised to lowercase on load via `str.strip().str.lower()`.

#### 8.2 CSV Upload

Users can upload their own login log CSV via the sidebar. The file must contain four columns: `timestamp`, `ip_address`, `username`, `status`. Column names are accepted case-insensitively.

The `validate_and_parse_upload()` function performs eight sequential validation steps:

| Step | Check | Outcome if failed |
|---|---|---|
| 1 | File is not empty | Hard error |
| 2 | Parseable as CSV | Hard error |
| 3 | All four required columns present | Hard error (names listed) |
| 4 | Entirely blank rows | Rows removed, warning shown |
| 5 | Exact duplicate rows | Rows removed, warning shown |
| 6 | Status values are `success` or `failed` | Bad rows removed (partial) or hard error (all bad) |
| 7 | Rows with missing required fields | Rows removed, warning shown |
| 8 | Timestamp parseable | Rows kept as NaT, warning shown |

If the upload fails validation, the app falls back silently to the built-in dataset and displays the error in the sidebar.

#### 8.3 Configurable Detection Threshold

A sidebar slider (range 1–20, default 5) sets the minimum number of failed login attempts required to flag an IP as suspicious. All detection, charts, KPI cards, and the downloadable report automatically update when the slider is moved.

The detection rule is strictly `failed_attempts >= threshold` (i.e., exactly at the threshold is included).

#### 8.4 KPI Cards

Five metric cards display at the top of the login-analysis tab:

| Card | Value (built-in sample at threshold 5) |
|---|---|
| Total Attempts | 44 |
| Successful | 7 |
| Failed | 37 |
| Invalid Status | 0 |
| Suspicious IPs | 5 |

If invalid status rows exist (e.g., from an uploaded file with inconsistent data), a yellow warning banner lists the unrecognised values. These rows are excluded from all counts and charts.

#### 8.5 Successful vs Failed Chart

A side-by-side bar chart compares the total count of successful and failed login attempts in the active, filtered dataset.

#### 8.6 Failed Login Counts by IP Address

A bar chart shows per-IP failed attempt counts in descending order. An expandable table below the chart shows the raw counts.

#### 8.7 Suspicious IP Table

For each IP that meets the threshold, the table shows:

| Column | Description |
|---|---|
| IP Address | The flagged IP |
| Failed Attempts | Exact count of failed logins from this IP |
| Risk Level | Heuristic label (see below) |
| Detection Reason | Human-readable explanation |

**Risk levels** (heuristics only — not proof of malicious intent):

| Label | Condition |
|---|---|
| 🔴 Critical | 10 or more failed attempts |
| 🟠 High | 7–9 failed attempts |
| 🟡 Medium | 5–6 failed attempts |

**Detection reasons** can include up to three signals:

1. *N failed attempts (≥T threshold)* — always present for flagged IPs
2. *Targeted N different username(s)* — same IP tried multiple accounts (credential stuffing pattern)
3. *Successful login after repeated failures* — failures followed by a success in timestamp order (possible break-in)

#### 8.8 Time-Window Filter

A sidebar dropdown restricts detection to records within the most recent N hours relative to the latest timestamp in the dataset: All records / Last 1 hour / 6 / 12 / 24 / 48 hours. An informational banner shows how many records are included when a filter is active.

#### 8.9 Raw Records Display

The full records table supports three additional display-only filters (these do not affect detection):

- **Show login status:** multiselect to show only `failed`, only `success`, or both
- **Suspicious IPs only:** checkbox to restrict the table to rows from flagged IPs

#### 8.10 Downloadable CSV Security Report

Clicking "Download Security Report" produces a UTF-8 CSV with two sections:

**Summary section:**

| field | value |
|---|---|
| Total login attempts | 44 |
| Successful logins | 7 |
| Failed logins | 37 |
| Invalid status rows | 0 |
| Detection threshold | 5 |
| Suspicious IPs detected | 5 |

**Suspicious IP section:** one row per flagged IP with failed count, risk label, and detection reason.

---

### Tab 2: URL Security Check

#### 8.11 HTTPS Detection

The tool checks whether the final response URL (after following redirects) begins with `https://`. If the scheme is missing from the user's input, `https://` is prepended automatically.

#### 8.12 Security Header Inspection

Six HTTP response headers are checked, split into two categories:

**Recommended** (widely expected on public websites):

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` (HSTS) | Instructs browsers to always use HTTPS |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `Content-Security-Policy` (CSP) | Restricts loadable scripts, styles, and resources |

**Situational** (context-dependent; absence is not necessarily a problem):

| Header | Purpose |
|---|---|
| `X-Frame-Options` | Controls iframe embedding (may be superseded by CSP `frame-ancestors`) |
| `Referrer-Policy` | Controls referrer information sent with requests |
| `Permissions-Policy` | Restricts browser feature access (camera, microphone, etc.) |

Each result shows whether the header was **Observed** or **Not observed**, the header's value if present, and a plain-language description. The tool explicitly states that absence of a header is not proof of a vulnerability, and that headers may be set by CDNs or proxies not visible in a single direct GET request. No letter grade or overall security judgement is issued.

#### 8.13 Error Handling

Five specific network exceptions are caught and shown as user-friendly messages:

- `SSLError` — invalid or expired certificate
- `ConnectionError` — host unreachable
- `Timeout` — request exceeded 10-second limit
- `InvalidURL` — malformed URL
- `RequestException` — any other network failure

---

## 9. Implementation Details

### detector.py — public functions

| Function | Purpose |
|---|---|
| `load_login_records(filepath)` | Reads the built-in CSV; normalises status to lowercase |
| `summarise_statuses(df)` | Returns total / success / failed / invalid counts from any DataFrame |
| `validate_and_parse_upload(file_obj)` | 8-step validation pipeline for user-uploaded files |
| `get_failed_attempts(df)` | Groups failed rows by IP, returns sorted DataFrame |
| `get_suspicious_ips(df, threshold)` | Filters `get_failed_attempts` result by threshold |
| `risk_label(failed_count, threshold)` | Returns Critical / High / Medium / Low / None label |
| `get_detection_reasons(df, ip, threshold)` | Returns a semicolon-separated reason string |
| `filter_by_time_window(df, hours)` | Returns rows within the most recent N hours |
| `build_report_df(df, threshold)` | Builds the two-section report DataFrame |

### url_checker.py — key design decisions

- `HEADERS_RECOMMENDED` and `HEADERS_SITUATIONAL` are defined as separate lists; `SECURITY_HEADERS` is their concatenation for backward compatibility.
- `check_url()` returns a plain dict — no Streamlit dependencies.
- The result dict contains `observed_count` and `total_headers` (integers) and pre-grouped lists (`recommended_found`, `recommended_missing`, `situational_found`, `situational_missing`) so `app.py` only renders, never re-classifies.
- No letter grade is computed or returned.

### app.py — structural decisions

- All sections inside `tab1` read from a single `df_filtered` variable; there is no separate data path per section.
- The sidebar is rendered before the tab blocks so its state (threshold, filters) is available inside both tabs.
- Upload validation errors cause a silent fallback to the built-in dataset with a sidebar message — the dashboard never crashes on bad input.

---

## 10. How to Install and Run the Project

### Step 1 — Clone or navigate to the project directory

```powershell
cd C:\Users\parul\Desktop\Cybershield
```

### Step 2 — Create a virtual environment (recommended)

```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install dependencies

```powershell
pip install -r requirements.txt
```

This installs: `streamlit`, `pandas`, `requests`, `pytest`.

### Step 4 — Run the Streamlit application

```powershell
python -m streamlit run app.py
```

Streamlit will open the application automatically in your default browser at `http://localhost:8501`.

### Step 5 — Run the automated tests

```powershell
python -m pytest tests/ -v
```

Expected output: **57 passed, 1 warning** (the warning is a benign pandas timestamp inference message, not a failure).

---

## 11. Testing and Results

### Test file

All tests are in [`tests/test_detector.py`](tests/test_detector.py). The test suite covers `detector.py` exclusively; `url_checker.py` was validated separately using Python's `unittest.mock` library.

### Test classes and coverage

| Test Class | Tests | What is covered |
|---|---|---|
| `TestGetFailedAttempts` | 5 | Correct counts, multiple IPs, no-failures case, empty DataFrame, sum reconciliation |
| `TestGetSuspiciousIps` | 9 | Exactly at threshold, one below, above, successful-only never flagged, multiple IPs, empty DataFrame, threshold changes, sample dataset (5 IPs), `>=` not `>` rule |
| `TestSummariseStatuses` | 5 | Count reconciliation, sample dataset exact counts, invalid value detection, all-valid case, empty DataFrame |
| `TestValidateAndParseUpload` | 13 | Valid CSV, empty file, missing column, multiple missing columns, all-bad status, partial bad status, case normalisation, missing IP field, duplicate rows, invalid timestamp (NaT), malformed binary, case-insensitive column names, accepted row count |
| `TestRiskLabel` | 9 | Critical at 10, above 10, High at 7 and 9, Medium at 5 and 6, Low at 1, None at 0, threshold respected |
| `TestGetDetectionReasons` | 5 | Basic failed count, multiple usernames, single username not mentioned, success-after-failures, success-only not triggered |
| `TestFilterByTimeWindow` | 5 | No filter, 1-hour window, all within window, empty DataFrame, NaT rows excluded |
| `TestBuildReportDf` | 6 | Required columns, summary metrics match `summarise_statuses`, suspicious IP section count, no-suspicious-IP row, CSV UTF-8 encoding, end-to-end reconciliation with dashboard values |
| **Total** | **57** | |

### Verified test run results

```
platform win32 -- Python 3.13.5, pytest-9.1.1, pluggy-1.7.0
collected 57 items

57 passed, 1 warning in 5.36s
```

The 1 warning is:

> `UserWarning: Could not infer format, so each element will be parsed individually, falling back to dateutil.`

This is raised by `pandas.to_datetime()` when processing intentionally malformed timestamp data in the upload-validation test. The behaviour under test (keeping the row with `NaT`) is correct; the warning is informational only.

### Key verified detection results (built-in sample dataset, threshold = 5)

| IP Address | Failed Attempts | Risk Level | Detection Reason |
|---|---|---|---|
| `192.0.2.88` | 8 | 🟠 High | 8 failed attempts (≥5 threshold) |
| `203.0.113.42` | 7 | 🟠 High | 7 failed attempts (≥5 threshold) |
| `198.51.100.7` | 6 | 🟡 Medium | 6 failed attempts (≥5 threshold) |
| `192.168.1.10` | 5 | 🟡 Medium | 5 failed attempts (≥5 threshold); Successful login after repeated failures |
| `203.0.113.99` | 5 | 🟡 Medium | 5 failed attempts (≥5 threshold) |

These results are produced directly by `get_suspicious_ips()` and `get_detection_reasons()` against the built-in dataset and are confirmed by both manual inspection of the CSV and by the automated test `test_sample_dataset_gives_5_suspicious_at_threshold_5`.

### Report CSV reconciliation (verified)

| Dashboard value | Report CSV value | Match |
|---|---|---|
| Total login attempts: 44 | 44 | ✔ |
| Successful logins: 7 | 7 | ✔ |
| Failed logins: 37 | 37 | ✔ |
| Invalid status rows: 0 | 0 | ✔ |
| Suspicious IPs detected: 5 | 5 | ✔ |

---

## 12. Screenshots

> **Note:** Screenshots cannot be automatically captured in this environment. The placeholders below describe exactly what each screenshot should show. Run `python -m streamlit run app.py` in your browser and take screenshots of each view for inclusion in a final submission.

### Screenshot 1 — Dashboard overview (Login Analysis tab, default state)

*Shows: page title "CyberShield — Security Analysis Toolkit", two tabs ("Login Analysis" and "URL Security Check"), sidebar with data source, threshold slider at 5, and filters. KPI cards showing 44 / 7 / 37 / 0 / 5.*

**Placeholder:** `screenshots/01_dashboard_overview.png`

### Screenshot 2 — Successful vs Failed chart

*Shows: side-by-side bar chart with "Successful" (7) and "Failed" (37) columns.*

**Placeholder:** `screenshots/02_status_chart.png`

### Screenshot 3 — Failed Login Counts by IP chart

*Shows: bar chart with 8 IP addresses on x-axis and failed attempt counts on y-axis. `192.0.2.88` bar is tallest at 8.*

**Placeholder:** `screenshots/03_failed_by_ip_chart.png`

### Screenshot 4 — Suspicious IP table

*Shows: table with 5 rows, columns: IP Address, Failed Attempts, Risk Level, Detection Reason. Red error banner above the table.*

**Placeholder:** `screenshots/04_suspicious_ip_table.png`

### Screenshot 5 — Download Security Report

*Shows: the download button and the expanded report preview table with Summary and Suspicious IP sections.*

**Placeholder:** `screenshots/05_download_report.png`

### Screenshot 6 — CSV Upload validation

*Shows: a CSV uploaded via the sidebar, with upload preview (rows accepted, warnings, 10-row data preview).*

**Placeholder:** `screenshots/06_csv_upload.png`

### Screenshot 7 — URL Security Check tab

*Shows: the URL input field, "Run Security Check" button, and (after a check) the disclaimer, HTTPS metric, observed-header count, progress bar, and the Recommended / Situational header groups.*

**Placeholder:** `screenshots/07_url_check_results.png`

### Screenshot 8 — Automated test results

*Shows: terminal output of `python -m pytest tests/ -v` with all 57 tests passing.*

**Placeholder:** `screenshots/08_test_results.png`

---

## 13. Limitations

1. **Simulated data only.** The built-in dataset contains 44 fictional records. The tool does not connect to any real authentication system, log aggregator, or SIEM platform.

2. **Threshold-based detection only.** Detection uses a simple count-based rule. It does not use anomaly detection, machine learning, statistical baselines, or behavioural profiling.

3. **No real-time monitoring.** The application analyses static CSV snapshots. It does not receive live log streams or alert in real time.

4. **URL check is a single GET request.** The URL security checker reads response headers from one direct HTTP request to one URL path at one moment in time. It does not crawl sub-pages, test API endpoints, check certificate validity in depth, or assess network-layer security.

5. **Header presence ≠ correct configuration.** A `Content-Security-Policy: *` header that permits everything still counts as "observed". The tool does not validate header values.

6. **No persistence.** Analysis results are not saved between browser sessions. The downloadable CSV report is generated on demand from the current session state.

7. **No IP geolocation or WHOIS data.**

8. **No automatic blocking or external system interaction.** CyberShield is read-only and observation-only. It never modifies any system.

9. **IPv6 addresses** are present in the code path but were not tested with real IPv6 login data.

---

## 14. Future Scope

| Enhancement | Description |
|---|---|
| Real log ingestion | Connect to syslog, auth.log, or a SIEM API instead of static CSVs |
| Machine-learning detection | Add anomaly detection using Isolation Forest or DBSCAN to flag unusual patterns not caught by a fixed threshold |
| Geolocation enrichment | Use a GeoIP database to show country / ASN information for flagged IPs |
| Alert notifications | Send email or webhook alerts when new suspicious IPs are detected |
| Header value analysis | Validate CSP directives and HSTS parameters, not just presence |
| Multi-page deep scan | Check security headers on multiple paths of the same site, not just the homepage |
| User authentication | Add login to the Streamlit app for multi-user environments |
| Database storage | Persist historical detection results for trend analysis over time |
| Docker packaging | Containerise the application for easy deployment |
| CI/CD integration | Run the pytest suite automatically on every code push via GitHub Actions |

---

## 15. Conclusion

CyberShield demonstrates two foundational cybersecurity concepts — threshold-based brute-force detection and HTTP security header inspection — in a practical, interactive web application built with Python and Streamlit.

The login-analysis module correctly identifies 5 suspicious IP addresses from a 44-record simulated dataset at the default threshold of 5 failed attempts, enriches each result with a risk level and detection reason, supports user-uploaded CSV files with robust validation, and generates a downloadable summary report. All of this functionality is covered by a 57-test automated suite, every one of which passes.

The URL security check module provides a transparent, non-judgmental view of HTTP security response headers, explicitly distinguishing recommended from situational headers and making clear that a single GET request cannot assess a site's overall security posture.

The project applies the same threshold-counting logic used by production tools such as `fail2ban`, demonstrates clean separation between UI code and business logic, and is documented sufficiently for a new learner to install, run, and extend it. It is a suitable portfolio piece for an IBM Cybersecurity course submission.

---

## 16. References

1. OWASP Foundation. *Testing for Brute Force (OTG-AUTHN-003).* OWASP Testing Guide v4.2. https://owasp.org/www-project-web-security-testing-guide/
2. Mozilla Developer Network. *HTTP Security Headers.* MDN Web Docs. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
3. Mozilla Developer Network. *Content Security Policy (CSP).* https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
4. Mozilla Developer Network. *Strict-Transport-Security.* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
5. Streamlit Inc. *Streamlit Documentation.* https://docs.streamlit.io/
6. pandas Development Team. *pandas Documentation.* https://pandas.pydata.org/docs/
7. Python Software Foundation. *Python 3 Documentation — urllib.parse.* https://docs.python.org/3/library/urllib.parse.html
8. fail2ban Project. *fail2ban: Ban hosts that cause multiple authentication errors.* https://www.fail2ban.org/

---

*Report generated from direct inspection of the CyberShield source code and live test execution.*
*All statistics, test results, and feature descriptions reflect the actual implementation.*
