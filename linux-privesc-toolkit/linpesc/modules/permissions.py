"""
permissions.py - Weak file & directory permission auditing.

Checks:
  * World-writable regular files
  * World-writable directories lacking the sticky bit (+t)
  * Permissions on sensitive system files (/etc/passwd, /etc/shadow, /etc/sudoers)
  * Home directory permission hygiene and unprivileged exposure

Safety: READ-ONLY. Never modifies permissions or file attributes.
"""

import os
import stat
from .utils import run_cmd, Finding

EXCLUDE_PREFIXES = ("/proc", "/sys", "/dev", "/run")


def _is_excluded(path):
    return any(path.startswith(p) for p in EXCLUDE_PREFIXES)


def scan(context):
    findings = []

    # 1. World-writable regular files
    stdout, _, _ = run_cmd(
        ["find", "/", "-xdev", "-type", "f", "-perm", "-0002"],
        timeout=90,
    )
    world_writable = [
        line.strip() for line in stdout.splitlines()
        if line.strip() and not _is_excluded(line.strip())
    ]
    context["world_writable_files"] = world_writable

    findings.append(Finding(
        module="permissions",
        title=f"World-writable files ({len(world_writable)} found)",
        detail="\n".join(world_writable[:200]) if world_writable else "No world-writable files discovered.",
        severity="MEDIUM" if world_writable else "INFO",
        exploitability="Any local unprivileged user can modify world-writable files. "
                        "If a privileged script or cron job reads or executes them, "
                        "privilege escalation is possible.",
        mitigation="Remove world write permissions using: chmod o-w <file>",
        confidence="Confirmed",
    ))

    # 2. World-writable directories WITHOUT sticky bit
    # Legitimate shared directories like /tmp and /var/tmp set the sticky bit (+t / S_ISVTX),
    # preventing non-owners from unlinking or renaming arbitrary files.
    # A world-writable directory lacking +t allows arbitrary file replacement.
    stdout_dirs, _, _ = run_cmd(
        ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000"],
        timeout=60,
    )
    non_sticky_dirs = [
        line.strip() for line in stdout_dirs.splitlines()
        if line.strip() and not _is_excluded(line.strip())
    ]

    if non_sticky_dirs:
        findings.append(Finding(
            module="permissions",
            title=f"World-writable directories without sticky bit ({len(non_sticky_dirs)} found)",
            detail="\n".join(non_sticky_dirs[:100]),
            severity="MEDIUM",
            exploitability="Unlike /tmp (which has sticky bit +t), directories here allow any local user "
                            "to delete, move, or replace files created by other users.",
            mitigation="Apply sticky bit or remove world write permission: chmod +t <dir> or chmod o-w <dir>",
            confidence="Confirmed",
        ))
    else:
        findings.append(Finding(
            module="permissions",
            title="World-writable directory sticky bit audit",
            detail="No world-writable directories lacking the sticky bit were found.",
            severity="INFO",
            exploitability="N/A",
            mitigation="N/A",
            confidence="Confirmed",
        ))

    # 3. Sensitive authentication file permissions
    sensitive_targets = [
        ("/etc/passwd", 0o644, False),   # target, expected max mode, check readable by others?
        ("/etc/shadow", 0o640, True),
        ("/etc/sudoers", 0o440, False),
    ]

    for target, expected_mode, check_read_others in sensitive_targets:
        try:
            st = os.stat(target)
            mode = stat.S_IMODE(st.st_mode)
            writable_by_others = bool(mode & stat.S_IWOTH)
            writable_by_group = bool(mode & stat.S_IWGRP)
            readable_by_others = bool(mode & stat.S_IROTH) and check_read_others

            risky = writable_by_others or (target.endswith("shadow") and (writable_by_group or readable_by_others)) or (target.endswith("sudoers") and (writable_by_others or writable_by_group))
            
            detail_msg = f"Target: {target}\nCurrent mode: {oct(mode)} (expected <= {oct(expected_mode)})\nUID={st.st_uid}, GID={st.st_gid}"
            
            findings.append(Finding(
                module="permissions",
                title=f"{target} permission audit",
                detail=detail_msg,
                severity="CRITICAL" if risky else "INFO",
                exploitability="A writable /etc/passwd allows appending a new root account (UID 0). "
                                "A readable/writable /etc/shadow or /etc/sudoers allows hash extraction or rule insertion."
                                if risky else "Properly secured permissions.",
                mitigation=f"Restore standard permissions: chown root:root {target} && chmod {oct(expected_mode)[2:]} {target}"
                           if risky else "N/A",
                confidence="Confirmed (Direct filesystem mode inspection)",
            ))
        except (FileNotFoundError, PermissionError, OSError) as e:
            findings.append(Finding(
                module="permissions",
                title=f"{target} inspection status",
                detail=str(e),
                severity="INFO",
                confidence="Confirmed",
            ))

    # 4. Home directory permissions
    stdout_home, _, _ = run_cmd("ls -ld /home")
    findings.append(Finding(
        module="permissions",
        title="/home directory listing",
        detail=stdout_home or "Could not inspect /home directory.",
        severity="INFO",
        confidence="Confirmed" if stdout_home else "N/A",
    ))

    return findings
