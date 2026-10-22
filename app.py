"""
app.py — CyberShield Suspicious Login Detector
Streamlit dashboard — all sections driven by a single active DataFrame.
"""

import streamlit as st
import pandas as pd
from detector import (
    load_login_records,
    get_failed_attempts,
    get_suspicious_ips,
    validate_and_parse_upload,
    summarise_statuses,
    risk_label,
    get_detection_reasons,
    filter_by_time_window,
    build_report_df,
)
from url_checker import check_url, SECURITY_HEADERS

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield — Suspicious Login Detector",
    page_icon="🛡️",
    layout="wide",
)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ CyberShield — Security Analysis Toolkit")
st.markdown(
    "An educational cybersecurity toolkit for analysing login records and "
    "inspecting website security headers. "
    "Built with simulated data for learning purposes — "
    "not intended as a replacement for professional security tooling."
)
st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🛡️ Login Analysis", "🌐 URL Security Check"])

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR  (relevant to Tab 1; visible on both tabs)
# ─────────────────────────────────────────────────────────────────────────────
st.sidebar.header("⚙️ Settings")

# ── 1. Data source ────────────────────────────────────────────────────────────
st.sidebar.subheader("📂 Data Source")
uploaded_file = st.sidebar.file_uploader(
    label="Upload a CSV login log",
    type=["csv"],
    help=(
        "Required columns: timestamp, ip_address, username, status. "
        "Leave empty to use the built-in 44-record sample dataset."
    ),
)

upload_row_stats = None   # set below if upload succeeds

if uploaded_file is not None:
    df_upload, upload_error, upload_warnings = validate_and_parse_upload(uploaded_file)
    if upload_error:
        st.sidebar.error(f"❌ Upload rejected: {upload_error}")
        st.sidebar.info("Falling back to the built-in sample dataset.")
        df = load_login_records()
        data_source = "Built-in sample (fallback — upload rejected)"
    else:
        df = df_upload
        data_source = f"Uploaded: **{uploaded_file.name}**"
        # Keep upload row stats for the preview section
        upload_row_stats = {
            "accepted": len(df),
            "warnings": upload_warnings,
        }
        for w in upload_warnings:
            st.sidebar.warning(f"⚠️ {w}")
else:
    df = load_login_records()
    data_source = "Built-in sample dataset (44 records)"

st.sidebar.caption(f"**Active:** {data_source}")
st.sidebar.divider()

# ── 2. Threshold ──────────────────────────────────────────────────────────────
st.sidebar.subheader("🎯 Detection Threshold")
threshold = st.sidebar.slider(
    label="Minimum failed attempts to flag",
    min_value=1,
    max_value=20,
    value=5,
    help="An IP is flagged as suspicious when its failed-login count reaches this number.",
)
st.sidebar.caption(
    f"IPs with **{threshold}+** failed attempts are flagged."
)
st.sidebar.divider()

# ── 3. Filters ────────────────────────────────────────────────────────────────
st.sidebar.subheader("🔎 Filters")

# Time window
time_options = {
    "All records": 0,
    "Last 1 hour": 1,
    "Last 6 hours": 6,
    "Last 12 hours": 12,
    "Last 24 hours": 24,
    "Last 48 hours": 48,
}
time_label  = st.sidebar.selectbox("Time window", list(time_options.keys()))
time_hours  = time_options[time_label]

# Status filter
status_filter = st.sidebar.multiselect(
    "Show login status",
    options=["failed", "success"],
    default=["failed", "success"],
    help="Filter the Raw Records table (does not affect detection).",
)

# Suspicious only toggle
suspicious_only = st.sidebar.checkbox(
    "Raw records: show suspicious IPs only",
    value=False,
    help="When checked, the Raw Records table shows only rows from flagged IPs.",
)

st.sidebar.divider()
st.sidebar.caption(
    "**Risk legend**\n\n"
    "🔴 Critical — 10+ failed attempts\n\n"
    "🟠 High — 7–9 failed attempts\n\n"
    "🟡 Medium — 5–6 failed attempts\n\n"
    "*Labels are heuristics, not proof of malicious activity.*"
)

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — Login Analysis  (all existing code, untouched)
# ─────────────────────────────────────────────────────────────────────────────
with tab1:

    # ── Apply time-window filter (for detection) ──────────────────────────────
    df_filtered = filter_by_time_window(df, time_hours)

    if time_hours and len(df_filtered) < len(df):
        st.info(
            f"⏱️ Time window active: showing **{len(df_filtered)}** of **{len(df)}** "
            f"records from the last **{time_hours} hour(s)**."
        )

    # ── Pre-compute — all values from df_filtered ─────────────────────────────
    stats            = summarise_statuses(df_filtered)
    total_attempts   = stats["total"]
    total_success    = stats["success"]
    total_failed     = stats["failed"]
    total_invalid    = stats["invalid"]
    invalid_vals     = stats["invalid_vals"]
    suspicious       = get_suspicious_ips(df_filtered, threshold=threshold)
    total_suspicious = len(suspicious)

    # ── Section 1 — Upload preview ────────────────────────────────────────────
    if upload_row_stats is not None:
        st.subheader("📤 Upload Preview")
        col_a, col_b = st.columns(2)
        col_a.metric("Rows accepted", upload_row_stats["accepted"])
        col_b.metric("Warnings", len(upload_row_stats["warnings"]))
        if upload_row_stats["warnings"]:
            with st.expander("View upload warnings"):
                for w in upload_row_stats["warnings"]:
                    st.warning(w)
        with st.expander("Preview first 10 rows of uploaded data"):
            st.dataframe(df.head(10), use_container_width=True)
        st.divider()

    # ── Section 2 — KPI Cards ─────────────────────────────────────────────────
    st.subheader("📈 Overview")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("🔢 Total Attempts",  total_attempts)
    col2.metric("✅ Successful",       total_success)
    col3.metric("❌ Failed",           total_failed)
    col4.metric(
        "⚠️ Invalid Status",
        total_invalid,
        help=(
            "Rows whose status is not 'success' or 'failed'. "
            + (f"Values: {', '.join(invalid_vals)}" if invalid_vals else "None found.")
        ),
    )
    col5.metric(
        "🚨 Suspicious IPs",
        total_suspicious,
        help=f"IPs with {threshold}+ failed attempts",
    )

    if total_invalid > 0:
        st.warning(
            f"⚠️ **{total_invalid}** row(s) with unrecognised status "
            f"({', '.join(repr(v) for v in invalid_vals)}) are excluded from all counts and charts."
        )

    st.divider()

    # ── Section 3 — Successful vs Failed chart ────────────────────────────────
    st.subheader("📊 Successful vs Failed Login Attempts")

    if total_attempts == 0:
        st.info("No records match the current filters.")
    else:
        status_pivot = (
            df_filtered[df_filtered["status"].isin(["success", "failed"])]
            .groupby("status")
            .size()
        )
        comparison_df = pd.DataFrame(
            {
                "Successful": [int(status_pivot.get("success", 0))],
                "Failed":     [int(status_pivot.get("failed",  0))],
            },
            index=["Login Attempts"],
        )
        st.bar_chart(comparison_df)

    st.divider()

    # ── Section 4 — Failed login counts by IP ────────────────────────────────
    st.subheader("🔍 Failed Login Counts by IP Address")

    failed_counts = get_failed_attempts(df_filtered)

    if failed_counts.empty:
        st.info("No failed login attempts in the current dataset / time window.")
    else:
        st.bar_chart(failed_counts.set_index("ip_address")["failed_attempts"])
        with st.expander("View detailed counts table"):
            st.dataframe(failed_counts, use_container_width=True)

    st.divider()

    # ── Section 5 — Suspicious IP table ──────────────────────────────────────
    st.subheader("🚨 Suspicious IP Addresses")

    with st.expander("ℹ️ How detection works"):
        st.markdown(
            f"""
An IP address is flagged as **suspicious** when it has **{threshold} or more failed login
attempts** in the active dataset.

Additional signals shown in the *Detection Reason* column:
- **Multiple usernames** — the same IP tried different accounts (credential stuffing pattern)
- **Success after failures** — a successful login followed earlier failures (possible break-in)

**Risk levels** are heuristics based on failed-attempt count:

| Risk | Threshold |
|---|---|
| 🔴 Critical | 10+ failed attempts |
| 🟠 High | 7–9 failed attempts |
| 🟡 Medium | 5–6 failed attempts |

*These labels are for educational purposes only and do not prove malicious intent.*
            """
        )

    if suspicious.empty:
        st.success(
            f"✅ No suspicious IPs detected at threshold **{threshold}**. "
            "All IPs have fewer failed attempts than the threshold."
        )
    else:
        st.error(
            f"⚠️ **{total_suspicious}** suspicious IP(s) detected "
            f"with **{threshold}+** failed login attempts."
        )
        rows = []
        for _, row in suspicious.iterrows():
            ip     = row["ip_address"]
            n_fail = int(row["failed_attempts"])
            rows.append({
                "IP Address":       ip,
                "Failed Attempts":  n_fail,
                "Risk Level":       risk_label(n_fail, threshold),
                "Detection Reason": get_detection_reasons(df_filtered, ip, threshold),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    st.divider()

    # ── Section 6 — Download report ───────────────────────────────────────────
    st.subheader("📥 Download Security Report")

    report_df  = build_report_df(df_filtered, threshold=threshold)
    report_csv = report_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Security Report (CSV)",
        data=report_csv,
        file_name="cybershield_report.csv",
        mime="text/csv",
        help="Downloads a CSV containing the summary metrics and suspicious IP details.",
    )

    with st.expander("Preview report contents"):
        st.dataframe(report_df, use_container_width=True)

    st.divider()

    # ── Section 7 — Raw login records ─────────────────────────────────────────
    st.subheader("📋 Raw Login Records")

    df_display = df_filtered.copy()

    if status_filter:
        df_display = df_display[df_display["status"].isin(status_filter)]
    else:
        st.info("No status selected — select at least one status in the sidebar to see records.")

    if suspicious_only and not suspicious.empty:
        flagged_ips = suspicious["ip_address"].tolist()
        df_display  = df_display[df_display["ip_address"].isin(flagged_ips)]

    st.markdown(
        f"Showing **{len(df_display)}** of **{total_attempts}** record(s) · "
        f"Source: {data_source}"
    )

    if df_display.empty:
        st.info("No records match the selected filters.")
    else:
        st.dataframe(df_display.reset_index(drop=True), use_container_width=True)

    st.divider()

    st.caption(
        "CyberShield uses threshold-based detection — the same core idea as real tools like "
        "fail2ban. This project uses **simulated data only** and is intended for learning purposes."
    )


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — URL Security Check
# ─────────────────────────────────────────────────────────────────────────────
with tab2:

    st.subheader("🌐 Website URL Security Check")
    st.markdown(
        "Enter a public website URL to check whether it uses **HTTPS** and "
        "which common **HTTP security response headers** are present. "
        "Only publicly visible response headers are inspected — no scanning, "
        "no crawling, and no data is stored."
    )

    with st.expander("ℹ️ What is checked and why"):
        rows_info = []
        for header_name, label, description in SECURITY_HEADERS:
            rows_info.append({"Header": label, "Purpose": description})
        st.markdown("**HTTPS** — encrypts traffic between the browser and the server.")
        st.table(pd.DataFrame(rows_info))
        st.caption(
            "Presence of a header does not guarantee correct configuration. "
            "Absence does not necessarily mean the site is insecure — some "
            "headers are set by proxies or CDNs not visible in this check."
        )

    url_input = st.text_input(
        label="Website URL",
        placeholder="https://example.com",
        help="Include or omit 'https://' — it will be added if missing.",
    )

    check_clicked = st.button("🔍 Run Security Check", type="primary")

    if check_clicked:
        if not url_input.strip():
            st.warning("Please enter a URL before running the check.")
        else:
            with st.spinner("Fetching security headers…"):
                result = check_url(url_input)

            if not result["reachable"]:
                st.error(f"❌ Could not reach the site.\n\n**Reason:** {result['error']}")
            else:
                # ── Disclaimer ────────────────────────────────────────────────
                st.info(
                    "**What this check does:** It sends a single HTTP GET request to the "
                    "URL you entered and reads the response headers that come back. "
                    "It does not assess the site's overall security posture. "
                    "Headers may be absent because they are set by a CDN or proxy not "
                    "visible in this request, or because they are not applicable to the site. "
                    "Absence of a header is **not** proof of a vulnerability."
                )

                if result["redirected"]:
                    st.info(f"↪️ Redirected to: `{result['final_url']}`")

                # ── Summary metrics ───────────────────────────────────────────
                observed  = result["observed_count"]
                total_h   = result["total_headers"]
                c1, c2, c3 = st.columns(3)
                c1.metric("HTTPS",              "✅ Yes" if result["https"] else "❌ No")
                c2.metric("Status Code",        str(result["status_code"]))
                c3.metric("Headers Observed",   f"{observed} of {total_h}")

                # Progress bar — purely informational, no grade implied
                st.caption(
                    f"{observed} of {total_h} security headers observed in this response."
                )
                st.progress(observed / total_h if total_h else 0)

                st.divider()

                # ── Recommended headers ───────────────────────────────────────
                st.markdown("#### Recommended headers")
                st.caption(
                    "These headers are widely expected on public websites. "
                    "If one is absent, it may be worth investigating — "
                    "but context matters before drawing conclusions."
                )
                for h in result["recommended_found"]:
                    with st.expander(f"✅ Observed — {h['label']}"):
                        st.markdown(f"**Purpose:** {h['description']}")
                        st.code(f"{h['header']}: {h['value']}", language=None)
                for h in result["recommended_missing"]:
                    with st.expander(f"➖ Not observed — {h['label']}"):
                        st.markdown(f"**Purpose:** {h['description']}")
                        st.caption(
                            "Not present in this response. This may be set at a different "
                            "layer (CDN, reverse proxy) or may not apply to this site."
                        )

                st.divider()

                # ── Situational headers ───────────────────────────────────────
                st.markdown("#### Situational headers")
                st.caption(
                    "These headers are context-dependent. Their absence does not "
                    "necessarily indicate a problem."
                )
                for h in result["situational_found"]:
                    with st.expander(f"✅ Observed — {h['label']}"):
                        st.markdown(f"**Purpose:** {h['description']}")
                        st.code(f"{h['header']}: {h['value']}", language=None)
                for h in result["situational_missing"]:
                    with st.expander(f"➖ Not observed — {h['label']}"):
                        st.markdown(f"**Purpose:** {h['description']}")
                        st.caption(
                            "Not present in this response. This is not necessarily "
                            "a concern — see the header description for context."
                        )

                st.divider()

                # ── HTTPS note ────────────────────────────────────────────────
                if not result["https"]:
                    st.warning(
                        "⚠️ The final response was not served over HTTPS. "
                        "Traffic between the browser and server may be unencrypted."
                    )

                st.caption(
                    f"Checked: `{result['final_url']}` · "
                    "Results reflect one HTTP GET request at the time of the check. "
                    "Header presence does not guarantee correct configuration."
                )
