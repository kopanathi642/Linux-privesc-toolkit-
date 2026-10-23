#!/usr/bin/env python3
"""
Linux Privilege Escalation Automation Toolkit
================================================
DETECTION-ONLY. This toolkit scans a Linux host for common privilege
escalation misconfigurations and produces a severity-ranked report. It
never attempts to exploit anything, modify system files, or escalate
its own privileges -- it only runs standard, read-only enumeration
commands (find, ls, systemctl, sudo -l, crontab -l, uname) and reports
what it sees.

Usage:
    python3 main.py [--out-dir OUTPUT_DIR] [--formats json,text,html]
                     [--skip MODULE1,MODULE2]

Modules:
    sysinfo     - user/kernel/OS fingerprint
    suid        - SUID/SGID binary discovery + GTFOBins matching
    permissions - world-writable files, /etc/passwd & /etc/shadow perms
    services    - sudo -l, systemd ExecStart writability
    cron        - crontab / /etc/cron.* writability
    kernel      - kernel version vs. known CVE ranges
"""

import argparse
import os
import sys
import datetime

from modules import sysinfo, suid_scan, permissions, services, cron_scan, kernel_scan, report

MODULES = {
    "sysinfo": sysinfo.gather,
    "suid": suid_scan.scan,
    "permissions": permissions.scan,
    "services": services.scan,
    "cron": cron_scan.scan,
    "kernel": kernel_scan.scan,
}


def main():
    parser = argparse.ArgumentParser(
        description="Linux Privilege Escalation Automation Toolkit (detection-only)."
    )
    parser.add_argument("--out-dir", default="./report_output",
                         help="Directory to write report files into.")
    parser.add_argument("--formats", default="json,text,html",
                         help="Comma-separated: json,text,html")
    parser.add_argument("--skip", default="",
                         help="Comma-separated module names to skip, e.g. suid,cron")
    args = parser.parse_args()

    skip = {m.strip() for m in args.skip.split(",") if m.strip()}
    formats = {f.strip() for f in args.formats.split(",") if f.strip()}

    os.makedirs(args.out_dir, exist_ok=True)

    context = {}
    all_findings = []

    print("[*] Linux Privilege Escalation Automation Toolkit")
    print("[*] Detection-only mode -- no exploitation will be attempted.\n")

    for name, func in MODULES.items():
        if name in skip:
            print(f"[-] Skipping module: {name}")
            continue
        print(f"[*] Running module: {name} ...")
        try:
            findings = func(context)
            all_findings.extend(findings)
            print(f"    -> {len(findings)} finding(s)")
        except Exception as e:
            print(f"    !! module '{name}' raised an error: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete. {len(all_findings)} total findings.")
    counts = report.summarize(all_findings)
    print("[*] Severity breakdown:",
          ", ".join(f"{k}={v}" for k, v in counts.items() if v))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    written = []
    if "json" in formats:
        p = report.to_json(all_findings, context,
                            os.path.join(args.out_dir, f"report_{stamp}.json"))
        written.append(p)
    if "text" in formats:
        p = report.to_text(all_findings, context,
                            os.path.join(args.out_dir, f"report_{stamp}.txt"))
        written.append(p)
    if "html" in formats:
        p = report.to_html(all_findings, context,
                            os.path.join(args.out_dir, f"report_{stamp}.html"))
        written.append(p)

    print("\n[*] Report(s) written:")
    for p in written:
        print(f"    - {p}")


if __name__ == "__main__":
    main()
