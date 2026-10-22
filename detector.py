"""
detector.py — CyberShield detection and data-processing logic.

All public functions accept a pandas DataFrame with columns:
    timestamp   (datetime64)
    ip_address  (str)
    username    (str)
    status      ('success' | 'failed')

No Streamlit imports here — this module is UI-independent and fully testable.
"""

import io
import pandas as pd

# ── Constants ─────────────────────────────────────────────────────────────────
REQUIRED_COLUMNS = {"timestamp", "ip_address", "username", "status"}
VALID_STATUSES   = {"success", "failed"}

# Risk thresholds (failed attempts → label).
# These are heuristics for demonstration purposes only.
# They do NOT prove malicious intent.
RISK_THRESHOLDS = [
    (10, "🔴 Critical"),   # 10 or more failed attempts
    (7,  "🟠 High"),       # 7–9 failed attempts
    (5,  "🟡 Medium"),     # 5–6 failed attempts
    (1,  "🟢 Low"),        # below suspicious threshold but >0 (not normally shown)
]


# ── Data loading ──────────────────────────────────────────────────────────────

def load_login_records(filepath="data/login_records.csv"):
    """
    Load the built-in login records CSV into a DataFrame.
    Normalises the status column (strip + lowercase) for consistency with
    validate_and_parse_upload().
    """
    df = pd.read_csv(filepath, parse_dates=["timestamp"])
    df["status"] = df["status"].astype(str).str.strip().str.lower()
    return df


# ── Status summary ────────────────────────────────────────────────────────────

def summarise_statuses(df):
    """
    Return a dict with counts of valid and invalid status values.

    Keys
    ----
    total        : int  — total rows
    success      : int  — rows where status == 'success'
    failed       : int  — rows where status == 'failed'
    invalid      : int  — rows with neither 'success' nor 'failed'
    invalid_vals : list — unique unrecognised status strings
    """
    total        = len(df)
    success      = int((df["status"] == "success").sum())
    failed       = int((df["status"] == "failed").sum())
    invalid_mask = ~df["status"].isin(VALID_STATUSES)
    invalid      = int(invalid_mask.sum())
    invalid_vals = sorted(df.loc[invalid_mask, "status"].unique().tolist())
    return {
        "total":        total,
        "success":      success,
        "failed":       failed,
        "invalid":      invalid,
        "invalid_vals": invalid_vals,
    }


# ── Upload validation ─────────────────────────────────────────────────────────

def validate_and_parse_upload(file_obj):
    """
    Validate and parse a CSV uploaded via Streamlit's file_uploader.

    Returns
    -------
    df       : pd.DataFrame | None  — cleaned DataFrame, or None on hard error
    error    : str | None           — fatal error message, or None on success
    warnings : list[str]            — non-fatal issues (rows dropped, etc.)
    """
    warnings = []

    # 1. Read raw bytes --------------------------------------------------------
    try:
        raw = file_obj.read()
        if len(raw) == 0:
            return None, "The uploaded file is empty.", warnings
        df = pd.read_csv(io.BytesIO(raw))
    except Exception as exc:
        return None, f"Could not parse the file as CSV: {exc}", warnings

    # 2. Normalise column names and check required columns --------------------
    df.columns = [c.strip().lower() for c in df.columns]
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        return (
            None,
            f"Missing required column(s): {', '.join(sorted(missing))}. "
            "Expected: timestamp, ip_address, username, status.",
            warnings,
        )

    # Keep only the columns we need
    df = df[list(REQUIRED_COLUMNS)].copy()

    # 3. Remove entirely blank rows -------------------------------------------
    before = len(df)
    df.dropna(how="all", inplace=True)
    if len(df) < before:
        warnings.append(f"Removed {before - len(df)} completely blank row(s).")

    if df.empty:
        return None, "The file contains no data rows after removing blank lines.", warnings

    # 4. Deduplicate exact duplicates -----------------------------------------
    before = len(df)
    df.drop_duplicates(inplace=True)
    dupes = before - len(df)
    if dupes:
        warnings.append(f"Removed {dupes} exact duplicate row(s).")

    # 5. Validate status values -----------------------------------------------
    df["status"] = df["status"].astype(str).str.strip().str.lower()
    bad_status   = ~df["status"].isin(VALID_STATUSES)
    n_bad        = int(bad_status.sum())
    if n_bad == len(df):
        return (
            None,
            f"All {n_bad} row(s) have an invalid 'status' value. "
            "Allowed values are 'success' and 'failed'.",
            warnings,
        )
    if n_bad > 0:
        bad_vals = sorted(df.loc[bad_status, "status"].unique().tolist())
        warnings.append(
            f"Removed {n_bad} row(s) with unrecognised status value(s) "
            f"{bad_vals} (allowed: 'success', 'failed')."
        )
        df = df[~bad_status].copy()

    # 6. Drop rows missing any required field ---------------------------------
    before = len(df)
    df.dropna(subset=list(REQUIRED_COLUMNS), inplace=True)
    dropped = before - len(df)
    if dropped:
        warnings.append(f"Removed {dropped} row(s) with missing field(s).")

    if df.empty:
        return None, "No valid data rows remain after cleaning.", warnings

    # 7. Parse timestamps (best-effort, non-fatal) ----------------------------
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        warnings.append(
            f"{bad_ts} row(s) have an unparseable timestamp — "
            "kept but shown as NaT."
        )

    # 8. Strip whitespace from text fields ------------------------------------
    df["ip_address"] = df["ip_address"].astype(str).str.strip()
    df["username"]   = df["username"].astype(str).str.strip()

    df = df.reset_index(drop=True)
    return df, None, warnings


# ── Core detection helpers ────────────────────────────────────────────────────

def get_failed_attempts(df):
    """
    Count failed logins per IP address.

    Returns a DataFrame with columns: ip_address, failed_attempts,
    sorted descending by failed_attempts.
    """
    failed = df[df["status"] == "failed"]
    if failed.empty:
        return pd.DataFrame(columns=["ip_address", "failed_attempts"])
    counts = (
        failed.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
        .reset_index(drop=True)
    )
    return counts


def get_suspicious_ips(df, threshold=5):
    """
    Return IPs with failed_attempts >= threshold.

    Parameters
    ----------
    df        : DataFrame with a 'status' and 'ip_address' column
    threshold : int — minimum failed attempts to be considered suspicious

    Returns a DataFrame with columns: ip_address, failed_attempts.
    """
    counts = get_failed_attempts(df)
    if counts.empty:
        return counts
    return counts[counts["failed_attempts"] >= threshold].reset_index(drop=True)


# ── Risk classification ───────────────────────────────────────────────────────

def risk_label(failed_count, threshold=5):
    """
    Return a human-readable risk label for an IP address.

    Labels are heuristics only — they indicate relative severity within
    this simulated dataset and are NOT proof of malicious activity.

    Parameters
    ----------
    failed_count : int  — number of failed attempts
    threshold    : int  — the configured suspicious threshold

    Returns
    -------
    str  e.g. '🔴 Critical'
    """
    for min_count, label in RISK_THRESHOLDS:
        if failed_count >= min_count:
            return label
    return "⬜ None"


# ── Detection reasons ─────────────────────────────────────────────────────────

def get_detection_reasons(df, ip, threshold=5):
    """
    Build a human-readable explanation for why an IP was flagged.

    Checks performed
    ----------------
    1. Failed attempts >= threshold (always present for flagged IPs)
    2. Multiple distinct usernames targeted from this IP
    3. Failed attempts followed by a successful login (possible break-in)

    Parameters
    ----------
    df        : full active DataFrame
    ip        : str — the IP address to explain
    threshold : int — configured threshold

    Returns
    -------
    str  — comma-separated reasons, e.g.
           "37 failed attempts (≥5 threshold); Targeted 3 usernames; Success after failures"
    """
    ip_df    = df[df["ip_address"] == ip].copy()
    reasons  = []

    # Reason 1: raw failed count
    n_failed = int((ip_df["status"] == "failed").sum())
    reasons.append(f"{n_failed} failed attempt(s) (≥{threshold} threshold)")

    # Reason 2: multiple usernames
    failed_df    = ip_df[ip_df["status"] == "failed"]
    n_usernames  = failed_df["username"].nunique()
    if n_usernames > 1:
        reasons.append(f"Targeted {n_usernames} different username(s)")

    # Reason 3: successful login after failures (possible credential success)
    ip_sorted = ip_df.sort_values("timestamp")
    statuses  = ip_sorted["status"].tolist()
    if "failed" in statuses and "success" in statuses:
        # Check there is at least one failed BEFORE a success
        first_success_idx = next(
            (i for i, s in enumerate(statuses) if s == "success"), None
        )
        if first_success_idx is not None and any(
            s == "failed" for s in statuses[:first_success_idx]
        ):
            reasons.append("Successful login after repeated failures")

    return "; ".join(reasons)


# ── Time-window filtering ─────────────────────────────────────────────────────

def filter_by_time_window(df, hours):
    """
    Return only rows within the most recent `hours` hours of the dataset.

    If hours is None or 0, the full DataFrame is returned unchanged.
    Rows with NaT timestamps are excluded from time-filtered results.

    Parameters
    ----------
    df    : DataFrame with a 'timestamp' column
    hours : int | None — look-back window in hours; None means no filter

    Returns
    -------
    pd.DataFrame
    """
    if not hours:
        return df
    valid_ts = df.dropna(subset=["timestamp"])
    if valid_ts.empty:
        return df
    cutoff = valid_ts["timestamp"].max() - pd.Timedelta(hours=hours)
    return df[df["timestamp"] >= cutoff].reset_index(drop=True)


# ── Report generation ─────────────────────────────────────────────────────────

def build_report_df(df, threshold=5):
    """
    Build a report DataFrame suitable for CSV download.

    The report has two sections concatenated with a blank separator row:

    Section A — Summary (one row per metric)
        metric, value

    Section B — Suspicious IP detail (one row per flagged IP)
        ip_address, failed_attempts, risk_level, detection_reasons

    Parameters
    ----------
    df        : active DataFrame
    threshold : int — configured suspicious threshold

    Returns
    -------
    pd.DataFrame  with columns: section, field, value
    """
    stats     = summarise_statuses(df)
    suspicious = get_suspicious_ips(df, threshold=threshold)

    # Section A: summary rows
    summary_rows = [
        ("Summary", "Total login attempts",   stats["total"]),
        ("Summary", "Successful logins",       stats["success"]),
        ("Summary", "Failed logins",           stats["failed"]),
        ("Summary", "Invalid status rows",     stats["invalid"]),
        ("Summary", "Detection threshold",     threshold),
        ("Summary", "Suspicious IPs detected", len(suspicious)),
    ]

    # Section B: per-IP detail rows
    detail_rows = []
    for _, row in suspicious.iterrows():
        ip      = row["ip_address"]
        n_fail  = int(row["failed_attempts"])
        label   = risk_label(n_fail, threshold)
        reasons = get_detection_reasons(df, ip, threshold)
        detail_rows.append(
            ("Suspicious IP", ip, f"Failed: {n_fail} | Risk: {label} | {reasons}")
        )

    if not detail_rows:
        detail_rows.append(
            ("Suspicious IP", "None", f"No IPs met the threshold of {threshold} failed attempts")
        )

    all_rows = summary_rows + detail_rows
    return pd.DataFrame(all_rows, columns=["section", "field", "value"])
