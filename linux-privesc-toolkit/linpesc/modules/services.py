"""
services.py - Misconfigured systemd services & sudo privilege checks.

Checks:
  * sudo -l output for NOPASSWD / ALL entries (non-interactive only)
  * systemd unit files & drop-in configurations that run as root but
    reference user-writable ExecStart binaries or parent directories.

Safety: READ-ONLY. Never invokes sudo interactively, never modifies service units.
"""

import os
from .utils import run_cmd, Finding


def _writable_by_current_user(path):
    """Safely check if path is writable by the current user."""
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


def _clean_exec_target(cmd_str):
    """
    Extract the primary executable path from a systemd ExecStart line,
    stripping systemd prefixes like '-', '@', '+', '!', '!!'.
    """
    token = cmd_str.split()[0] if cmd_str.split() else ""
    # Strip systemd command prefixes
    token = token.lstrip("-@+!")
    return token.strip("\"'")


def _parse_unit_file(fpath):
    """
    Parse a systemd unit or drop-in file, ignoring comments (# and ;)
    and returning active (User, [ExecStart targets]).
    """
    user = None
    exec_starts = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("User="):
                    user = line.split("=", 1)[1].strip()
                elif line.startswith("ExecStart="):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        target = _clean_exec_target(val)
                        if target:
                            exec_starts.append(target)
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return user, exec_starts


def scan(context):
    findings = []

    # 1. Non-interactive sudo check (sudo -n -l)
    stdout, stderr, rc = run_cmd("sudo -n -l")
    if rc == 0 and stdout:
        risky_lines = [
            l for l in stdout.splitlines()
            if "NOPASSWD" in l or "ALL" in l
        ]
        findings.append(Finding(
            module="services",
            title="sudo -l configuration",
            detail=stdout,
            severity="HIGH" if risky_lines else "INFO",
            exploitability="Rules permitting NOPASSWD execution of interpreters, editors, "
                            "or shell utilities can lead directly to root privilege escalation."
                            if risky_lines else "Standard authenticated sudo rules.",
            mitigation="Follow the principle of least privilege in /etc/sudoers; avoid NOPASSWD "
                       "on general-purpose utilities." if risky_lines else "N/A",
            confidence="Confirmed",
        ))
    else:
        findings.append(Finding(
            module="services",
            title="sudo -l status",
            detail=stderr or "sudo not configured for this user, or requires password (non-interactive check skipped).",
            severity="INFO",
            exploitability="N/A",
            mitigation="N/A",
            confidence="Confirmed",
        ))

    # 2. Systemd unit files & drop-ins
    if context.get("is_root"):
        findings.append(Finding(
            module="services",
            title="systemd ExecStart writability check skipped",
            detail="Toolkit is running in a root session. Every file is writable by root, "
                   "so writability checks are non-discriminative. Re-run as a low-privilege user "
                   "for an authentic audit.",
            severity="INFO",
            confidence="Confirmed",
        ))
        return findings

    unit_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
    ]

    flagged = []
    checked_count = 0

    for d in unit_dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except (PermissionError, OSError):
            continue

        for fname in entries:
            if not fname.endswith(".service"):
                continue
            unit_path = os.path.join(d, fname)
            checked_count += 1

            unit_user, exec_targets = _parse_unit_file(unit_path)

            # Check drop-in configurations: <unit_name>.d/*.conf
            dropin_dir = os.path.join(d, f"{fname}.d")
            if os.path.isdir(dropin_dir):
                try:
                    for cname in os.listdir(dropin_dir):
                        if cname.endswith(".conf"):
                            cpath = os.path.join(dropin_dir, cname)
                            d_user, d_execs = _parse_unit_file(cpath)
                            if d_user:
                                unit_user = d_user
                            exec_targets.extend(d_execs)
                except (PermissionError, OSError):
                    pass

            run_as_root = (unit_user is None) or (unit_user.lower() == "root")
            if not run_as_root:
                continue

            for target in exec_targets:
                if not target.startswith("/"):
                    continue
                if os.path.exists(target):
                    # Check executable file writability
                    if _writable_by_current_user(target):
                        flagged.append((unit_path, target, "target executable is writable"))
                    else:
                        # Check parent directory writability
                        parent_dir = os.path.dirname(target)
                        if parent_dir and os.path.isdir(parent_dir) and _writable_by_current_user(parent_dir):
                            flagged.append((unit_path, target, f"parent directory '{parent_dir}' is writable"))

    context["units_checked"] = checked_count

    if flagged:
        for unit, target, reason in flagged:
            findings.append(Finding(
                module="services",
                title=f"Vulnerable systemd ExecStart: {os.path.basename(unit)}",
                detail=f"Unit file: {unit}\nExecStart target: {target}\nCondition: {reason}\nService runs as root.",
                severity="CRITICAL",
                exploitability="A local non-root user can overwrite or replace this binary, which executes "
                                "with root privileges when the service starts or restarts.",
                mitigation=f"Restrict write permissions on '{target}' and its enclosing directory: "
                           f"chown root:root {target} && chmod 755 {target}",
                confidence="Confirmed (Direct file/directory write permission verified)",
            ))
    else:
        findings.append(Finding(
            module="services",
            title="systemd service ExecStart targets",
            detail=f"Audited {checked_count} service unit files. No root services referencing "
                   f"user-writable executables or user-writable parent directories were found.",
            severity="INFO",
            exploitability="N/A",
            mitigation="N/A",
            confidence="Confirmed",
        ))

    return findings
