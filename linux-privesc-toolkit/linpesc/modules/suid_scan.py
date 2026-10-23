"""
suid_scan.py - Scan for SUID/SGID binaries and file capabilities (getcap).

Safety note: This module only DETECTS. It never executes the flagged
binaries, invokes exploit payloads, or alters file attributes.
"""

import os
from .utils import run_cmd, Finding

# Binaries documented on GTFOBins as abusable for privilege escalation
# when SUID/SGID bit is set. Used purely as a detection filter.
GTFOBINS_SUID_RISK = {
    "awk", "find", "perl", "python", "python3", "vim", "vi", "nmap",
    "less", "more", "man", "nano", "cp", "mv", "bash", "sh", "env",
    "tar", "zip", "unzip", "ftp", "gdb", "ruby", "lua", "php", "node",
    "git", "docker", "chmod", "chown", "openssl", "ssh", "scp", "rsync",
    "pkexec", "sudo", "doas", "systemctl", "aria2c", "base64", "curl", "wget"
}

RISKY_CAPABILITIES = {
    "cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override",
    "cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module",
}


def scan(context):
    findings = []

    # 1. SUID/SGID Scan: ensure grouped find expressions and regular files only (-type f)
    cmd = ["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"]
    stdout, stderr, rc = run_cmd(cmd, timeout=90)

    binaries = [line.strip() for line in stdout.splitlines() if line.strip()]
    context["suid_binaries"] = binaries

    high_risk = []
    for path in binaries:
        name = os.path.basename(path)
        if name in GTFOBINS_SUID_RISK:
            high_risk.append(path)

    findings.append(Finding(
        module="suid_scan",
        title=f"SUID/SGID binaries discovered ({len(binaries)} total)",
        detail="\n".join(binaries) if binaries else "None found or unreadable on this host.",
        severity="INFO",
        exploitability="N/A",
        mitigation="Periodically audit SUID/SGID inventory against baseline.",
        confidence="Confirmed",
    ))

    for path in high_risk:
        findings.append(Finding(
            module="suid_scan",
            title=f"Potential GTFOBins SUID match: {path}",
            detail=f"Binary '{path}' has SUID/SGID bit set and matches a known "
                   f"utility name in the GTFOBins catalog.",
            severity="HIGH",
            exploitability="GTFOBins documents potential privilege escalation techniques "
                            "for this utility name. Actual exploitability depends on binary "
                            "compilation, environment variables, and execution context.",
            mitigation=f"Review if SUID/SGID bit is required. If not, strip permissions with: "
                       f"chmod u-s,g-s {path}",
            confidence="Preliminary (Name match against GTFOBins; requires operational review)",
        ))

    # 2. Linux File Capabilities (getcap) enumeration
    cap_out, cap_err, cap_rc = run_cmd(["getcap", "-r", "/"], timeout=60)
    if cap_rc == 127 or "not found" in cap_err.lower() or "not found" in cap_out.lower():
        findings.append(Finding(
            module="suid_scan",
            title="Linux file capabilities check",
            detail="The 'getcap' utility is not available on this system (libcap2-bin not installed).",
            severity="INFO",
            exploitability="N/A",
            mitigation="Install libcap2-bin if capability auditing is desired.",
            confidence="N/A",
        ))
    elif cap_rc == 0 and cap_out:
        cap_lines = [line.strip() for line in cap_out.splitlines() if line.strip()]
        findings.append(Finding(
            module="suid_scan",
            title=f"File capabilities identified ({len(cap_lines)} found)",
            detail="\n".join(cap_lines),
            severity="INFO",
            exploitability="N/A",
            mitigation="Review assigned POSIX capabilities to ensure principle of least privilege.",
            confidence="Confirmed",
        ))

        for line in cap_lines:
            line_lower = line.lower()
            if any(rcap in line_lower for rcap in RISKY_CAPABILITIES):
                parts = line.split()
                target_file = parts[0] if parts else line
                findings.append(Finding(
                    module="suid_scan",
                    title=f"High-privilege capability assigned: {target_file}",
                    detail=f"Capability assignment: {line}",
                    severity="HIGH",
                    exploitability="Dangerous capabilities like cap_setuid or cap_dac_override "
                                    "can allow callers to manipulate process credentials or bypass DAC.",
                    mitigation=f"Remove unnecessary capabilities using: setcap -r {target_file}",
                    confidence="Confirmed",
                ))
    else:
        findings.append(Finding(
            module="suid_scan",
            title="Linux file capabilities check",
            detail="No elevated file capabilities discovered (or read access restricted).",
            severity="INFO",
            exploitability="N/A",
            mitigation="N/A",
            confidence="Confirmed",
        ))

    return findings
