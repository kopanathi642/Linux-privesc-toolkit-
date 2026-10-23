"""
sysinfo.py - STEP 1: System Information Collection

Gathers: current user, groups, UID/GID, kernel version, OS release,
and whether the current session already has root.
"""

import os
from .utils import run_cmd, Finding


def gather(context):
    findings = []

    whoami, _, _ = run_cmd("whoami")
    groups_out, _, _ = run_cmd("id")
    kernel, _, _ = run_cmd("uname -a")
    os_release, _, _ = run_cmd("cat /etc/os-release")

    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    context["user"] = whoami
    context["id"] = groups_out
    context["kernel"] = kernel
    context["os_release"] = os_release
    context["is_root"] = is_root

    findings.append(Finding(
        module="sysinfo",
        title="Session identity",
        detail=f"user={whoami} | {groups_out}",
        severity="INFO",
        exploitability="N/A",
        mitigation="N/A",
    ))

    findings.append(Finding(
        module="sysinfo",
        title="Kernel / OS fingerprint",
        detail=f"{kernel}\n{os_release}",
        severity="INFO",
        exploitability="N/A",
        mitigation="N/A",
    ))

    if is_root:
        findings.append(Finding(
            module="sysinfo",
            title="Already running as root",
            detail="The toolkit was invoked with root privileges. "
                    "Scan results reflect what root can see on this host, "
                    "not what an unprivileged attacker could reach.",
            severity="INFO",
            exploitability="N/A",
            mitigation="Re-run as a low-privilege user for a realistic "
                       "attacker-eye-view audit.",
        ))

    return findings
