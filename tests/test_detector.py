"""
tests/test_detector.py
======================
Automated tests for detector.py.

Run with:  python -m pytest tests/ -v
"""

import io
import pytest
import pandas as pd

from detector import (
    load_login_records,
    summarise_statuses,
    validate_and_parse_upload,
    get_failed_attempts,
    get_suspicious_ips,
    risk_label,
    get_detection_reasons,
    filter_by_time_window,
    build_report_df,
    VALID_STATUSES,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_df(rows):
    """
    Build a minimal DataFrame from a list of (ip, status) tuples.
    Timestamps increase by 1 minute per row.
    """
    records = []
    for i, (ip, status) in enumerate(rows):
        records.append({
            "timestamp":  pd.Timestamp("2024-01-01 08:00:00") + pd.Timedelta(minutes=i),
            "ip_address": ip,
            "username":   "testuser",
            "status":     status,
        })
    return pd.DataFrame(records)


def make_df_with_usernames(rows):
    """
    Build a DataFrame from (ip, status, username) tuples.
    """
    records = []
    for i, (ip, status, user) in enumerate(rows):
        records.append({
            "timestamp":  pd.Timestamp("2024-01-01 08:00:00") + pd.Timedelta(minutes=i),
            "ip_address": ip,
            "username":   user,
            "status":     status,
        })
    return pd.DataFrame(records)


class FakeUpload:
    """Simulates a Streamlit UploadedFile object."""
    def __init__(self, content: bytes, name: str = "test.csv"):
        self._content = content
        self.name = name

    def read(self):
        return self._content


def csv_bytes(text: str) -> bytes:
    return text.strip().encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# get_failed_attempts
# ─────────────────────────────────────────────────────────────────────────────

class TestGetFailedAttempts:

    def test_counts_only_failed(self):
        df = make_df([("1.1.1.1", "failed"), ("1.1.1.1", "success"), ("1.1.1.1", "failed")])
        result = get_failed_attempts(df)
        assert result.loc[result["ip_address"] == "1.1.1.1", "failed_attempts"].iloc[0] == 2

    def test_multiple_ips(self):
        df = make_df([
            ("1.1.1.1", "failed"), ("1.1.1.1", "failed"),
            ("2.2.2.2", "failed"),
        ])
        result = get_failed_attempts(df)
        assert len(result) == 2
        assert result.iloc[0]["ip_address"] == "1.1.1.1"   # sorted descending
        assert result.iloc[0]["failed_attempts"] == 2

    def test_no_failures_returns_empty(self):
        df = make_df([("1.1.1.1", "success"), ("2.2.2.2", "success")])
        result = get_failed_attempts(df)
        assert result.empty

    def test_empty_dataframe_returns_empty(self):
        df = pd.DataFrame(columns=["timestamp", "ip_address", "username", "status"])
        result = get_failed_attempts(df)
        assert result.empty

    def test_sum_equals_total_failed_rows(self):
        """get_failed_attempts totals must reconcile with raw failed row count."""
        df = load_login_records()
        fc  = get_failed_attempts(df)
        raw_failed = int((df["status"] == "failed").sum())
        assert int(fc["failed_attempts"].sum()) == raw_failed


# ─────────────────────────────────────────────────────────────────────────────
# get_suspicious_ips — threshold boundary tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGetSuspiciousIps:

    def test_exactly_at_threshold_is_flagged(self):
        df = make_df([("1.1.1.1", "failed")] * 5)
        result = get_suspicious_ips(df, threshold=5)
        assert len(result) == 1
        assert result.iloc[0]["ip_address"] == "1.1.1.1"

    def test_one_below_threshold_is_not_flagged(self):
        df = make_df([("1.1.1.1", "failed")] * 4)
        result = get_suspicious_ips(df, threshold=5)
        assert result.empty

    def test_above_threshold_is_flagged(self):
        df = make_df([("1.1.1.1", "failed")] * 9)
        result = get_suspicious_ips(df, threshold=5)
        assert len(result) == 1
        assert result.iloc[0]["failed_attempts"] == 9

    def test_successful_logins_never_flagged(self):
        df = make_df([("1.1.1.1", "success")] * 10)
        result = get_suspicious_ips(df, threshold=1)
        assert result.empty

    def test_multiple_ips_only_flagged_ips_returned(self):
        df = make_df(
            [("1.1.1.1", "failed")] * 6 +
            [("2.2.2.2", "failed")] * 3 +
            [("3.3.3.3", "failed")] * 5
        )
        result = get_suspicious_ips(df, threshold=5)
        flagged = set(result["ip_address"].tolist())
        assert flagged == {"1.1.1.1", "3.3.3.3"}
        assert "2.2.2.2" not in flagged

    def test_empty_dataframe(self):
        df = pd.DataFrame(columns=["timestamp", "ip_address", "username", "status"])
        result = get_suspicious_ips(df, threshold=5)
        assert result.empty

    def test_threshold_change_changes_results(self):
        df = make_df([("1.1.1.1", "failed")] * 5)
        assert len(get_suspicious_ips(df, threshold=5)) == 1
        assert len(get_suspicious_ips(df, threshold=6)) == 0

    def test_sample_dataset_gives_5_suspicious_at_threshold_5(self):
        df = load_login_records()
        result = get_suspicious_ips(df, threshold=5)
        assert len(result) == 5

    def test_rule_is_gte_not_gt(self):
        """Threshold means >=, not >."""
        df = make_df([("1.1.1.1", "failed")] * 5)
        assert not get_suspicious_ips(df, threshold=5).empty
        assert get_suspicious_ips(df, threshold=6).empty


# ─────────────────────────────────────────────────────────────────────────────
# summarise_statuses
# ─────────────────────────────────────────────────────────────────────────────

class TestSummariseStatuses:

    def test_counts_add_up_to_total(self):
        df = load_login_records()
        s = summarise_statuses(df)
        assert s["success"] + s["failed"] + s["invalid"] == s["total"]

    def test_sample_dataset_exact_counts(self):
        df = load_login_records()
        s = summarise_statuses(df)
        assert s["total"]   == 44
        assert s["success"] == 7
        assert s["failed"]  == 37
        assert s["invalid"] == 0

    def test_invalid_status_detected(self):
        df = pd.DataFrame({"status": ["failed", "success", "unknown", "WEIRD"]})
        s = summarise_statuses(df)
        assert s["invalid"] == 2
        assert set(s["invalid_vals"]) == {"unknown", "WEIRD"}

    def test_all_valid_gives_zero_invalid(self):
        df = make_df([("1.1.1.1", "failed"), ("2.2.2.2", "success")])
        s = summarise_statuses(df)
        assert s["invalid"] == 0
        assert s["invalid_vals"] == []

    def test_empty_dataframe(self):
        df = pd.DataFrame({"status": []})
        s = summarise_statuses(df)
        assert s["total"] == 0
        assert s["success"] == 0
        assert s["failed"]  == 0
        assert s["invalid"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# validate_and_parse_upload
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateAndParseUpload:

    def _valid_csv(self, extra_rows=""):
        return csv_bytes(
            "timestamp,ip_address,username,status\n"
            "2024-01-01 09:00:00,1.1.1.1,alice,failed\n"
            "2024-01-01 09:01:00,1.1.1.1,alice,failed\n"
            + extra_rows
        )

    def test_valid_csv_returns_dataframe(self):
        df, err, warns = validate_and_parse_upload(FakeUpload(self._valid_csv()))
        assert err is None
        assert df is not None
        assert len(df) == 2

    def test_empty_file_returns_error(self):
        df, err, _ = validate_and_parse_upload(FakeUpload(b""))
        assert df is None
        assert "empty" in err.lower()

    def test_missing_column_returns_error(self):
        content = csv_bytes("timestamp,ip_address,username\n2024-01-01,1.1.1.1,alice")
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        assert df is None
        assert "status" in err

    def test_missing_multiple_columns(self):
        content = csv_bytes("timestamp,username\n2024-01-01,alice")
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        assert df is None
        assert "ip_address" in err
        assert "status" in err

    def test_all_bad_status_returns_error(self):
        content = csv_bytes(
            "timestamp,ip_address,username,status\n"
            "2024-01-01,1.1.1.1,alice,INVALID\n"
            "2024-01-01,2.2.2.2,bob,NOPE"
        )
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        assert df is None
        assert "invalid" in err.lower()

    def test_partial_bad_status_rows_dropped_with_warning(self):
        content = csv_bytes(
            "timestamp,ip_address,username,status\n"
            "2024-01-01,1.1.1.1,alice,failed\n"
            "2024-01-01,2.2.2.2,bob,BADVAL"
        )
        df, err, warns = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert df is not None
        assert len(df) == 1
        assert any("unrecognised" in w.lower() or "removed" in w.lower() for w in warns)

    def test_status_case_normalised(self):
        content = csv_bytes(
            "timestamp,ip_address,username,status\n"
            "2024-01-01,1.1.1.1,alice,FAILED\n"
            "2024-01-01,2.2.2.2,bob,Success"
        )
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert set(df["status"].tolist()) == {"failed", "success"}

    def test_missing_ip_row_dropped_with_warning(self):
        content = csv_bytes(
            "timestamp,ip_address,username,status\n"
            "2024-01-01,,alice,failed\n"
            "2024-01-01,2.2.2.2,bob,success"
        )
        df, err, warns = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert len(df) == 1
        assert any("missing" in w.lower() or "removed" in w.lower() for w in warns)

    def test_duplicate_rows_removed_with_warning(self):
        row = "2024-01-01 09:00:00,1.1.1.1,alice,failed\n"
        content = csv_bytes(
            "timestamp,ip_address,username,status\n" + row * 3
        )
        df, err, warns = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert len(df) == 1
        assert any("duplicate" in w.lower() for w in warns)

    def test_invalid_timestamp_kept_as_nat_with_warning(self):
        content = csv_bytes(
            "timestamp,ip_address,username,status\n"
            "NOT-A-DATE,1.1.1.1,alice,failed\n"
            "2024-01-01 09:00:00,2.2.2.2,bob,success"
        )
        df, err, warns = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert len(df) == 2
        assert df["timestamp"].isna().sum() == 1
        assert any("timestamp" in w.lower() or "nat" in w.lower() for w in warns)

    def test_malformed_csv_returns_error(self):
        """Binary garbage should return an error, not crash."""
        content = b"\x00\x01\x02\x03GARBAGE"
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        # Either parse fails outright OR columns are missing — both acceptable
        assert df is None

    def test_column_names_case_insensitive(self):
        content = csv_bytes(
            "TIMESTAMP,IP_ADDRESS,USERNAME,STATUS\n"
            "2024-01-01,1.1.1.1,alice,failed"
        )
        df, err, _ = validate_and_parse_upload(FakeUpload(content))
        assert err is None
        assert df is not None

    def test_accepted_count_matches_len(self):
        df, err, _ = validate_and_parse_upload(FakeUpload(self._valid_csv()))
        assert err is None
        assert len(df) == 2


# ─────────────────────────────────────────────────────────────────────────────
# risk_label
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskLabel:

    def test_critical_at_10(self):
        assert "Critical" in risk_label(10)

    def test_critical_above_10(self):
        assert "Critical" in risk_label(15)

    def test_high_at_7(self):
        assert "High" in risk_label(7)

    def test_high_at_9(self):
        assert "High" in risk_label(9)

    def test_medium_at_5(self):
        assert "Medium" in risk_label(5)

    def test_medium_at_6(self):
        assert "Medium" in risk_label(6)

    def test_low_at_1(self):
        assert "Low" in risk_label(1)

    def test_none_at_0(self):
        assert risk_label(0) == "⬜ None"

    def test_threshold_respected(self):
        """risk_label with threshold 3 at count 3 should still return Medium or higher."""
        label = risk_label(3, threshold=3)
        assert label != "⬜ None"


# ─────────────────────────────────────────────────────────────────────────────
# get_detection_reasons
# ─────────────────────────────────────────────────────────────────────────────

class TestGetDetectionReasons:

    def test_basic_failed_count_in_reason(self):
        df = make_df([("1.1.1.1", "failed")] * 5)
        reason = get_detection_reasons(df, "1.1.1.1", threshold=5)
        assert "5" in reason
        assert "failed" in reason.lower()

    def test_multiple_usernames_detected(self):
        df = make_df_with_usernames([
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "bob"),
            ("1.1.1.1", "failed", "carol"),
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "bob"),
        ])
        reason = get_detection_reasons(df, "1.1.1.1", threshold=5)
        assert "3" in reason
        assert "username" in reason.lower()

    def test_single_username_not_mentioned(self):
        df = make_df([("1.1.1.1", "failed")] * 5)
        reason = get_detection_reasons(df, "1.1.1.1", threshold=5)
        assert "username" not in reason.lower()

    def test_success_after_failures_detected(self):
        df = make_df_with_usernames([
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "failed", "alice"),
            ("1.1.1.1", "success", "alice"),
        ])
        reason = get_detection_reasons(df, "1.1.1.1", threshold=5)
        assert "success" in reason.lower()

    def test_success_only_not_triggered(self):
        """Only successes — no 'success after failures' reason expected."""
        df = make_df([("1.1.1.1", "success")] * 5)
        reason = get_detection_reasons(df, "1.1.1.1", threshold=1)
        assert "after" not in reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# filter_by_time_window
# ─────────────────────────────────────────────────────────────────────────────

class TestFilterByTimeWindow:

    def _make_time_df(self):
        """5 rows spread over 5 hours."""
        base = pd.Timestamp("2024-01-01 10:00:00")
        return pd.DataFrame([
            {"timestamp": base - pd.Timedelta(hours=4), "ip_address": "1.1.1.1",
             "username": "u", "status": "failed"},
            {"timestamp": base - pd.Timedelta(hours=3), "ip_address": "1.1.1.1",
             "username": "u", "status": "failed"},
            {"timestamp": base - pd.Timedelta(hours=2), "ip_address": "2.2.2.2",
             "username": "u", "status": "failed"},
            {"timestamp": base - pd.Timedelta(hours=1), "ip_address": "2.2.2.2",
             "username": "u", "status": "failed"},
            {"timestamp": base,                          "ip_address": "3.3.3.3",
             "username": "u", "status": "success"},
        ])

    def test_no_filter_returns_all(self):
        df = self._make_time_df()
        assert len(filter_by_time_window(df, 0)) == 5
        assert len(filter_by_time_window(df, None)) == 5

    def test_1_hour_returns_only_recent(self):
        df = self._make_time_df()
        result = filter_by_time_window(df, 1)
        # Only rows within 1 hour of max timestamp (base): hours 0 and -1
        assert len(result) == 2

    def test_all_records_within_window_included(self):
        df = self._make_time_df()
        result = filter_by_time_window(df, 5)
        assert len(result) == 5

    def test_empty_df_returns_empty(self):
        df = pd.DataFrame(columns=["timestamp", "ip_address", "username", "status"])
        result = filter_by_time_window(df, 2)
        assert result.empty

    def test_nat_timestamps_excluded_from_window(self):
        df = self._make_time_df()
        df.loc[0, "timestamp"] = pd.NaT
        result = filter_by_time_window(df, 1)
        # NaT row should not appear in time-filtered result
        assert result["timestamp"].isna().sum() == 0


# ─────────────────────────────────────────────────────────────────────────────
# build_report_df
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildReportDf:

    def test_report_has_required_columns(self):
        df = load_login_records()
        report = build_report_df(df, threshold=5)
        assert set(report.columns) == {"section", "field", "value"}

    def test_summary_metrics_match_summarise_statuses(self):
        df = load_login_records()
        stats  = summarise_statuses(df)
        report = build_report_df(df, threshold=5)
        summary = report[report["section"] == "Summary"]

        def get_val(field):
            row = summary[summary["field"] == field]
            assert not row.empty, f"Field '{field}' not found in report summary"
            return int(row.iloc[0]["value"])

        assert get_val("Total login attempts")   == stats["total"]
        assert get_val("Successful logins")      == stats["success"]
        assert get_val("Failed logins")          == stats["failed"]
        assert get_val("Invalid status rows")    == stats["invalid"]
        assert get_val("Detection threshold")    == 5
        assert get_val("Suspicious IPs detected") == 5

    def test_report_has_suspicious_ip_section(self):
        df = load_login_records()
        report = build_report_df(df, threshold=5)
        detail = report[report["section"] == "Suspicious IP"]
        assert len(detail) == 5    # 5 suspicious IPs in sample data

    def test_no_suspicious_ips_gives_none_row(self):
        df = make_df([("1.1.1.1", "success")] * 10)
        report = build_report_df(df, threshold=5)
        detail = report[report["section"] == "Suspicious IP"]
        assert len(detail) == 1
        assert detail.iloc[0]["field"] == "None"

    def test_report_csv_is_valid_utf8(self):
        df = load_login_records()
        report = build_report_df(df, threshold=5)
        csv_bytes_out = report.to_csv(index=False).encode("utf-8")
        decoded = csv_bytes_out.decode("utf-8")
        assert "Summary" in decoded
        assert "Suspicious IP" in decoded

    def test_report_counts_consistent_with_dashboard(self):
        """
        End-to-end: report summary numbers must match what the dashboard shows.
        This is the reconciliation test.
        """
        df      = load_login_records()
        stats   = summarise_statuses(df)
        susp    = get_suspicious_ips(df, threshold=5)
        report  = build_report_df(df, threshold=5)
        summary = report[report["section"] == "Summary"]

        for field, expected in [
            ("Total login attempts",   stats["total"]),
            ("Successful logins",      stats["success"]),
            ("Failed logins",          stats["failed"]),
            ("Invalid status rows",    stats["invalid"]),
            ("Suspicious IPs detected", len(susp)),
        ]:
            row = summary[summary["field"] == field].iloc[0]
            assert int(row["value"]) == expected, (
                f"Report field '{field}': got {row['value']}, expected {expected}"
            )
