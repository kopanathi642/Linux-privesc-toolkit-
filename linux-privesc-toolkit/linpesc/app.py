from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

# Paths and Constants
ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "report_output"
MAIN_SCRIPT = ROOT / "main.py"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
MODULES = ["sysinfo", "suid", "permissions", "services", "cron", "kernel"]

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4f",
    "HIGH": "#fa541c",
    "MEDIUM": "#faad14",
    "LOW": "#1890ff",
    "INFO": "#8c8c8c",
}


def newest_json_report() -> Path | None:
    """Return the most recently modified report_*.json file in REPORT_DIR."""
    if not REPORT_DIR.exists():
        return None
    files = list(REPORT_DIR.glob("report_*.json"))
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def load_report(path: Path | None) -> dict[str, Any] | None:
    """Safely load and validate the JSON audit report schema."""
    if path is None or not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return None
        data.setdefault("summary", {})
        data.setdefault("findings", [])
        data.setdefault("host_context", {})
        if not isinstance(data["findings"], list):
            data["findings"] = []
        return data
    except (OSError, json.JSONDecodeError):
        return None


def run_scan(selected_modules: list[str]) -> tuple[int, str, str]:
    """Execute main.py safely with sys.executable and arguments list (no shell=True)."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    skipped = [name for name in MODULES if name not in selected_modules]
    command = [
        sys.executable,
        str(MAIN_SCRIPT),
        "--out-dir",
        str(REPORT_DIR),
        "--formats",
        "json,text,html",
    ]
    if skipped:
        command.extend(["--skip", ",".join(skipped)])
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Scan timed out after 180 seconds. Try selecting fewer modules."
    except OSError as exc:
        return 1, "", f"Could not start scanner process: {exc}"


def finding_value(finding: dict[str, Any], *keys: str, default: str = "") -> str:
    """Extract first non-empty value among keys with fallback default."""
    for key in keys:
        value = finding.get(key)
        if value is not None and value != "":
            return str(value)
    return default


def render_dashboard():
    st.set_page_config(
        page_title="Linux PrivEsc Audit Toolkit",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom Polished Dark Security Dashboard Styling
    st.markdown("""
    <style>
      .stApp {
        background: #090d12;
        color: #e6edf3;
      }
      [data-testid="stSidebar"] {
        background: #0d131a;
        border-right: 1px solid #1f2937;
      }
      [data-testid="stMetric"] {
        background: #111823;
        border: 1px solid #243042;
        padding: 16px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
      }
      [data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 700;
      }
      div[data-testid="stDataFrame"] {
        border: 1px solid #243042;
        border-radius: 10px;
      }
      .hero {
        padding: 1.4rem 1.6rem;
        background: linear-gradient(135deg, #101926 0%, #0d141f 100%);
        border: 1px solid #243042;
        border-radius: 14px;
        margin-bottom: 1.2rem;
      }
      .hero h1 {
        font-size: 1.65rem;
        margin: 0 0 6px 0;
        color: #f0f6fc;
        letter-spacing: -0.02em;
      }
      .muted {
        color: #8b949e;
        font-size: 0.92rem;
        margin: 0;
      }
      .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        color: #ffffff;
      }
      .report-card {
        background: #111823;
        border: 1px solid #243042;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 12px;
      }
    </style>
    """, unsafe_allow_html=True)

    # Sidebar Navigation
    with st.sidebar:
        st.title("🛡️ PrivEsc Audit")
        st.caption("Defensive Security Automation Dashboard")
        st.divider()
        page = st.radio(
            "Navigation",
            ["Overview", "Run Scan", "Findings", "Reports", "About & Safety"],
            label_visibility="collapsed",
        )
        st.divider()
        st.markdown("""
        **Audit Scope:**
        * Local Host Assessment
        * Detection-Only Mode
        * Read-Only Execution
        """)
        st.caption("Authorized defensive auditing only.")

    # Load newest report data
    report_path = newest_json_report()
    data = load_report(report_path)
    findings = data.get("findings", []) if data else []
    summary = data.get("summary", {}) if data else {}
    context = data.get("host_context", {}) if data else {}

    st.markdown("""
    <div class="hero">
      <h1>Linux Privilege Escalation Audit Toolkit</h1>
      <p class="muted">Automated detection of misconfigurations, weak permissions, abusable SUID binaries, and known CVE indicators.</p>
    </div>
    """, unsafe_allow_html=True)

    # -------------------------------------------------------------
    # PAGE: OVERVIEW
    # -------------------------------------------------------------
    if page == "Overview":
        st.subheader("Security Posture Overview")

        # Metrics Row
        m_cols = st.columns(5)
        for col, severity in zip(m_cols, SEVERITIES):
            val = int(summary.get(severity, 0) or 0)
            col.metric(severity, val)

        st.write("")

        left, right = st.columns([1.2, 1.0])
        with left:
            st.markdown("#### Host Context & Execution State")
            if report_path and data:
                st.markdown(f"""
                * **Latest Report:** `{report_path.name}`
                * **Generated At:** `{data.get('generated_at', 'Unknown')}`
                * **User Session:** `{context.get('user', 'Unknown')}`
                * **UID / GID Context:** `{context.get('id', 'Unknown')}`
                * **Kernel Release:** `{context.get('kernel', 'Unknown')}`
                * **Root Status:** `{"Root (UID 0)" if context.get("is_root") else "Unprivileged User"}`
                """)
            else:
                st.info("No audit reports found in `report_output/`. Navigate to **Run Scan** to execute your first audit.")

            st.markdown("#### Module Breakdown")
            if findings:
                mod_counts: dict[str, int] = {}
                for f in findings:
                    m_name = f.get("module", "unknown")
                    mod_counts[m_name] = mod_counts.get(m_name, 0) + 1
                st.dataframe(
                    [{"Module": k, "Findings": v} for k, v in sorted(mod_counts.items())],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.write("No findings to display.")

        with right:
            st.markdown("#### Findings by Severity")
            chart_data = {s: int(summary.get(s, 0) or 0) for s in SEVERITIES}
            st.bar_chart(chart_data)

            st.caption("ℹ️ **Triage Note:** Severity classification aids defensive remediation prioritization. Version-only CVE matches are preliminary indicators subject to vendor security backports.")

    # -------------------------------------------------------------
    # PAGE: RUN SCAN
    # -------------------------------------------------------------
    elif page == "Run Scan":
        st.subheader("Execute Local Defensive Audit")

        st.warning("⚠️ **Notice:** This toolkit audits the host where the Python process runs. It performs strictly read-only enumeration and never invokes automatic exploit payloads.")

        selected = st.multiselect(
            "Select detection modules to execute:",
            MODULES,
            default=MODULES,
            help="Choose which audit modules will be invoked by main.py",
        )

        if "scanning" not in st.session_state:
            st.session_state["scanning"] = False

        run_btn = st.button(
            "▶ Run Audit Scan",
            type="primary",
            disabled=not selected or st.session_state["scanning"],
        )

        if run_btn:
            st.session_state["scanning"] = True
            with st.spinner("Executing read-only enumeration modules…"):
                code, stdout, stderr = run_scan(selected)
            st.session_state["scanning"] = False

            if stdout:
                with st.expander("Scanner Console Output", expanded=True):
                    st.code(stdout)
            if stderr:
                st.warning(f"Scanner stderr:\n{stderr}")

            if code == 0:
                st.success("✅ Audit completed successfully! Refreshing dashboard findings.")
                st.rerun()
            else:
                st.error(f"Scanner process terminated with exit code {code}.")

    # -------------------------------------------------------------
    # PAGE: FINDINGS
    # -------------------------------------------------------------
    elif page == "Findings":
        st.subheader("Vulnerability & Misconfiguration Explorer")

        if not findings:
            st.info("No findings found in the latest audit report. Run a scan or inspect the report directory.")
        else:
            all_severities = [s for s in SEVERITIES if any(finding_value(f, "severity") == s for f in findings)] or SEVERITIES
            all_modules = sorted({finding_value(f, "module", default="unknown") for f in findings})

            f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
            with f_col1:
                severity_filter = st.multiselect("Filter by Severity", SEVERITIES, default=all_severities)
            with f_col2:
                module_filter = st.multiselect("Filter by Module", all_modules, default=all_modules)
            with f_col3:
                search_query = st.text_input("Search findings (title, detail, mitigation)")

            filtered = []
            for item in findings:
                sev = finding_value(item, "severity", default="INFO").upper()
                mod = finding_value(item, "module", default="unknown")
                haystack = (
                    finding_value(item, "title") + " " +
                    finding_value(item, "detail") + " " +
                    finding_value(item, "mitigation") + " " +
                    finding_value(item, "exploitability")
                ).lower()

                if sev in severity_filter and mod in module_filter:
                    if not search_query or search_query.lower() in haystack:
                        filtered.append(item)

            st.caption(f"Showing **{len(filtered)}** of **{len(findings)}** total findings.")

            # Summary Table
            table_rows = [{
                "Severity": finding_value(f, "severity", default="INFO").upper(),
                "Module": finding_value(f, "module", default="unknown"),
                "Finding Title": finding_value(f, "title", default="Untitled"),
                "Confidence": finding_value(f, "confidence", default="Confirmed"),
            } for f in filtered]
            st.dataframe(table_rows, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("### Detailed Finding Cards")

            for idx, item in enumerate(filtered, start=1):
                title = finding_value(item, "title", default=f"Finding {idx}")
                sev = finding_value(item, "severity", default="INFO").upper()
                mod = finding_value(item, "module", default="unknown")
                confidence = finding_value(item, "confidence", default="Confirmed")
                exploitability = finding_value(item, "exploitability", default="Not assessed")
                mitigation = finding_value(item, "mitigation", default="Review and remediate according to standard hardening policies.")
                detail = finding_value(item, "detail", default="No evidence details provided.")

                with st.expander(f"[{sev}] {title} — ({mod})"):
                    c_left, c_right = st.columns([1, 1])
                    with c_left:
                        st.write("**Module:**", mod)
                        st.write("**Severity Level:**", sev)
                    with c_right:
                        st.write("**Confidence / State:**", confidence)

                    st.markdown("**Evidence / Output Details:**")
                    st.code(detail)

                    st.markdown("**Exploitability Analysis:**")
                    st.info(exploitability)

                    st.markdown("**Suggested Mitigation:**")
                    st.success(mitigation)

    # -------------------------------------------------------------
    # PAGE: REPORTS
    # -------------------------------------------------------------
    elif page == "Reports":
        st.subheader("Generated Audit Reports")
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_files = sorted(REPORT_DIR.glob("report_*.*"), key=lambda p: p.stat().st_mtime, reverse=True)

        if not report_files:
            st.info("No saved audit reports in `report_output/`. Run an audit to generate JSON, HTML, and text reports.")
        else:
            st.caption(f"Found {len(report_files)} report artifacts in `{REPORT_DIR}`.")

            for rpath in report_files:
                mod_time = datetime.fromtimestamp(rpath.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                size_kb = rpath.stat().st_size / 1024.0
                suffix = rpath.suffix.lower()

                mime_types = {
                    ".json": "application/json",
                    ".html": "text/html",
                    ".txt": "text/plain",
                }
                mime = mime_types.get(suffix, "application/octet-stream")

                with st.container(border=True):
                    r_col1, r_col2 = st.columns([3, 1])
                    with r_col1:
                        st.markdown(f"**`{rpath.name}`**")
                        st.caption(f"Format: {suffix.upper().lstrip('.')} • Size: {size_kb:.1f} KB • Modified: {mod_time}")
                    with r_col2:
                        with rpath.open("rb") as handle:
                            st.download_button(
                                label=f"⬇️ Download {suffix.upper().lstrip('.')}",
                                data=handle.read(),
                                file_name=rpath.name,
                                mime=mime,
                                key=f"dl-{rpath.name}",
                                use_container_width=True,
                            )

    # -------------------------------------------------------------
    # PAGE: ABOUT & SAFETY
    # -------------------------------------------------------------
    else:
        st.subheader("About & Defensive Architecture")

        st.markdown("""
        ### 🛡️ Defensive Security Mission
        The **Linux Privilege Escalation Automation Toolkit** is an automated, detection-only security auditing framework built for security engineers, system administrators, and authorized penetration testers.

        ### 🔒 Safety Model & Limitations
        1. **Strictly Detection-Only**: Every module runs passive, read-only system enumeration commands (`find`, `uname`, `sudo -n -l`, `crontab -l`, `getcap`). It **never** executes exploits, creates persistence, steals credentials, alters user files, or modifies permissions.
        2. **Host-Local Audit**: The toolkit audits the machine where the Python process executes. When launched via a web dashboard, it audits the host running the Python server, not remote browser clients.
        3. **Target Platform**: Designed specifically for **Linux** environments (Ubuntu, Debian, Red Hat, Kali, Arch). On Windows, it gracefully executes fallback detection, but a Linux host or WSL2 environment is required to inspect real POSIX privilege escalations.
        4. **Preliminary CVE Matching**: Kernel and package version checks match running versions against publicly cataloged CVE ranges. Because enterprise distributions (such as Ubuntu, Debian, and RHEL) routinely backport security patches into older upstream version numbers, findings are flagged as *Preliminary* and require validation against the distribution's security tracker.
        5. **Authorization Requirement**: Only execute this toolkit on systems you personally own or have explicit written authorization to evaluate.
        """)

    st.divider()
    st.caption("Linux Privilege Escalation Automation Toolkit • Defensive Security & Compliance")


if __name__ == "__main__" or st.runtime.exists():
    render_dashboard()
