"""
kernel_scan.py - Kernel version fingerprinting and vulnerability matching.

Compares running kernel version against a curated list of publicly disclosed
privilege escalation CVEs. Also inspects polkit / pkexec (CVE-2021-4034)
separately from kernel checks.

Important: Detection-only. Never claims confirmed exploitability for version-only
matches, as Linux distributions routinely backport security fixes without changing
upstream version numbers.
"""

import re
from .utils import run_cmd, Finding

# Known kernel-specific privilege escalation CVEs (exclusive upper bound)
KNOWN_KERNEL_CVES = [
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe",
        "min": (5, 8, 0),
        "max": (5, 16, 11),
        "note": "Arbitrary file overwrite via pipe buffer flag mishandling.",
    },
    {
        "cve": "CVE-2016-5195",
        "name": "Dirty COW",
        "min": (2, 6, 22),
        "max": (4, 8, 3),
        "note": "Race condition in copy-on-write memory handling.",
    },
    {
        "cve": "CVE-2023-2640",
        "name": "GameOverlay / OverlayFS",
        "min": (5, 15, 0),
        "max": (5, 19, 0),
        "note": "Ubuntu OverlayFS permission-handling privilege escalation.",
    },
    {
        "cve": "CVE-2023-32233",
        "name": "Netfilter nf_tables UAF",
        "min": (5, 14, 0),
        "max": (6, 3, 2),
        "note": "Use-after-free in Netfilter nf_tables component.",
    },
]


def _parse_version(uname_r):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", uname_r)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def scan(context):
    findings = []

    uname_r, _, _ = run_cmd("uname -r")
    version = _parse_version(uname_r)

    findings.append(Finding(
        module="kernel_scan",
        title="Running kernel release",
        detail=uname_r or "Unable to determine kernel version (non-Linux or command unavailable).",
        severity="INFO",
        confidence="Confirmed" if uname_r else "N/A",
    ))

    # 1. Kernel CVE version-range checks
    if version:
        for entry in KNOWN_KERNEL_CVES:
            if entry["min"] <= version < entry["max"]:
                findings.append(Finding(
                    module="kernel_scan",
                    title=f"Potential kernel CVE match: {entry['cve']} ({entry['name']})",
                    detail=f"Running kernel release '{uname_r}' falls within the upstream "
                           f"affected range [{'.'.join(map(str, entry['min']))} - {'.'.join(map(str, entry['max']))}) "
                           f"for {entry['cve']}. {entry['note']}",
                    severity="HIGH",
                    exploitability="Preliminary indicator. Upstream kernel version matches known vulnerability window; "
                                    "however, Linux distribution maintainers frequently backport security patches. "
                                    "This toolkit does not verify or run active exploits.",
                    mitigation="Review package changelogs and kernel package versions from your distribution vendor "
                               "(e.g., `apt changelog linux-image-...` or `rpm -q --changelog kernel`). Update and reboot if unpatched.",
                    confidence="Preliminary (Version match only; check distribution security tracker for backports)",
                ))

        # EOL heuristic (pre-5.x)
        if version[0] < 5:
            findings.append(Finding(
                module="kernel_scan",
                title="Kernel appears outdated / legacy",
                detail=f"Running kernel '{uname_r}' is pre-5.x series, which is past end-of-life "
                       f"on mainstream enterprise and LTS Linux distributions.",
                severity="MEDIUM",
                exploitability="Legacy kernels lack modern security mitigations (e.g., lockdown, eBPF hardening) "
                                "and accumulate unpatched public CVEs.",
                mitigation="Upgrade host operating system and kernel to an actively supported LTS distribution release.",
                confidence="Confirmed",
            ))

    # 2. PwnKit (CVE-2021-4034) polkit check - NOT a kernel CVE
    pkexec_path, _, pkexec_rc = run_cmd("which pkexec")
    if pkexec_rc == 0 and pkexec_path:
        # Check pkexec version or package version
        pk_ver, _, _ = run_cmd("pkexec --version")
        findings.append(Finding(
            module="kernel_scan",
            title="Polkit / pkexec presence check (CVE-2021-4034 evaluation)",
            detail=f"pkexec binary found at '{pkexec_path}'. Version output: {pk_ver or 'N/A'}",
            severity="LOW",
            exploitability="PwnKit (CVE-2021-4034) is a polkit vulnerability, not a kernel vulnerability. "
                            "Systems with unpatched polkit (released before Jan 2022) are vulnerable. "
                            "Most modern distributions have patched polkit via standard package updates.",
            mitigation="Verify polkit package version against distribution security notices: "
                       "`dpkg -s policykit-1` or `rpm -q polkit`.",
            confidence="Preliminary (Package presence only; requires package changelog verification)",
        ))
    else:
        findings.append(Finding(
            module="kernel_scan",
            title="Polkit pkexec check",
            detail="pkexec utility was not found in PATH.",
            severity="INFO",
            exploitability="N/A",
            mitigation="N/A",
            confidence="Confirmed",
        ))

    return findings
