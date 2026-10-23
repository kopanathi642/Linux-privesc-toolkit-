"""
cron_scan.py - Cron job privilege escalation and hijacking detection.

Checks:
  * Current user crontab (crontab -l)
  * System-wide cron directories (/etc/cron.d, /etc/cron.daily, etc.) and /etc/crontab
  * Writability of scripts executed by root cron tasks
  * Writability of enclosing directories for cron scripts (path replacement)
  * Ambiguous or relative command paths in cron jobs

Safety: READ-ONLY. Never alters cron tables or scripts.
"""

import os
import shlex
from .utils import run_cmd, Finding

CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def _is_env_or_comment(line):
    """Detect comments or environment variable assignments (e.g., PATH=...)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return True
    first_token = s.split()[0]
    if "=" in first_token and not first_token.startswith("/"):
        return True
    return False


def _extract_command_tokens(line, is_system_cron=True):
    """
    Extract executable tokens from a cron line.
    System crontabs (/etc/crontab, /etc/cron.d/*) have 6 timing/user fields:
      min hour dom mon dow user command [args]
    User crontabs have 5 timing fields:
      min hour dom mon dow command [args]
    """
    tokens = line.split()
    timing_offset = 6 if is_system_cron else 5
    if len(tokens) <= timing_offset:
        return None, []

    cron_user = tokens[5] if is_system_cron else None
    cmd_tokens = tokens[timing_offset:]
    return cron_user, cmd_tokens


def _parse_script_targets(cmd_tokens):
    """
    Identify potential script/executable targets from command tokens,
    accounting for interpreter wrappers (python, bash, sh, perl).
    """
    if not cmd_tokens:
        return []

    targets = []
    # Filter out common shell operators
    filtered = []
    for tok in cmd_tokens:
        if tok in (";", "&&", "||", "|", ">", ">>", "2>&1", "<"):
            break
        filtered.append(tok)

    if not filtered:
        return []

    first = filtered[0]

    # Handle interpreters like: /bin/bash /opt/scripts/backup.sh
    interpreters = {"sh", "bash", "python", "python3", "perl", "ruby", "php"}
    base_first = os.path.basename(first)

    if base_first in interpreters and len(filtered) > 1:
        for candidate in filtered[1:]:
            if candidate.startswith("-"):
                continue
            if candidate.startswith("/"):
                targets.append(candidate)
                break
    elif first.startswith("/"):
        targets.append(first)
    else:
        # Relative path command
        targets.append(first)

    return targets


def scan(context):
    findings = []
    running_as_root = bool(context.get("is_root"))

    # 1. User crontab
    stdout, stderr, rc = run_cmd("crontab -l")
    findings.append(Finding(
        module="cron_scan",
        title="Current user crontab",
        detail=stdout if rc == 0 else "No crontab for current user (or restricted).",
        severity="INFO",
        confidence="Confirmed",
    ))

    if running_as_root:
        findings.append(Finding(
            module="cron_scan",
            title="Cron writability check scope",
            detail="Toolkit is running in a root session. Every file is writable by root; "
                   "re-run as an unprivileged user to identify authentic cron hijacking paths.",
            severity="INFO",
            confidence="Confirmed",
        ))

    # 2. System-wide /etc/crontab and cron directories
    cron_entries = []  # (source, user, raw_line, [targets])

    if os.path.isfile("/etc/crontab"):
        try:
            with open("/etc/crontab", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if _is_env_or_comment(line):
                        continue
                    user, cmd_toks = _extract_command_tokens(line, is_system_cron=True)
                    targets = _parse_script_targets(cmd_toks)
                    cron_entries.append(("/etc/crontab", user or "root", line.strip(), targets))
        except (PermissionError, OSError):
            pass

    for d in CRON_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except (PermissionError, OSError):
            continue

        for fname in entries:
            fpath = os.path.join(d, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if _is_env_or_comment(line):
                            continue
                        user, cmd_toks = _extract_command_tokens(line, is_system_cron=(d == "/etc/cron.d"))
                        targets = _parse_script_targets(cmd_toks)
                        cron_entries.append((fpath, user or "root", line.strip(), targets))
            except (PermissionError, OSError):
                continue

    # 3. Analyze cron entries for hijacking conditions
    vulnerable_targets = []
    manual_review_targets = []

    for source, user, line, targets in cron_entries:
        is_root_job = (user is None or user.lower() == "root")

        for target in targets:
            # Check relative paths (potential PATH hijacking)
            if not target.startswith("/"):
                manual_review_targets.append((source, line, target, "Uses relative command path; verify PATH configuration"))
                continue

            if not running_as_root:
                if os.path.exists(target):
                    # Check script writability
                    if os.access(target, os.W_OK):
                        vulnerable_targets.append((source, user, target, "target script is writable by current user"))
                    else:
                        # Check parent directory writability
                        parent_dir = os.path.dirname(target)
                        if parent_dir and os.path.isdir(parent_dir) and os.access(parent_dir, os.W_OK):
                            vulnerable_targets.append((source, user, target, f"enclosing directory '{parent_dir}' is writable"))

    if vulnerable_targets:
        for source, user, target, reason in vulnerable_targets:
            findings.append(Finding(
                module="cron_scan",
                title=f"Vulnerable cron script: {os.path.basename(target)}",
                detail=f"Source: {source}\nJob runs as: {user}\nScript: {target}\nCondition: {reason}",
                severity="CRITICAL",
                exploitability="A non-root user can overwrite or replace this script. The next time the cron daemon "
                                f"executes the job as {user}, arbitrary commands will run with {user} privileges.",
                mitigation=f"Restrict write access to the script and parent directory: "
                           f"chown root:root {target} && chmod 755 {target}",
                confidence="Confirmed (Direct write access verified)",
            ))
    elif cron_entries:
        findings.append(Finding(
            module="cron_scan",
            title="Cron script writability audit",
            detail=f"Audited {len(cron_entries)} active cron jobs across system crontabs. "
                   f"No root-run tasks with user-writable targets or directories were detected.",
            severity="INFO",
            confidence="Confirmed",
        ))

    if manual_review_targets:
        sample = manual_review_targets[:10]
        findings.append(Finding(
            module="cron_scan",
            title=f"Cron jobs requiring manual review ({len(manual_review_targets)} flagged)",
            detail="\n".join(f"[{src}] {line} -> ({note})" for src, line, tgt, note in sample),
            severity="LOW",
            exploitability="Relative command paths in cron jobs rely on the cron PATH definition. "
                            "If any directory in PATH is writable by non-root, binary hijacking is possible.",
            mitigation="Ensure all cron jobs use fully qualified absolute paths (e.g., /usr/local/bin/script.sh).",
            confidence="Preliminary",
        ))

    return findings
