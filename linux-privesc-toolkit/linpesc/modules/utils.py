"""
utils.py - shared helpers for all scanner modules.

Design note: every module in this toolkit is READ-ONLY / DETECTION-ONLY.
No module ever modifies files, escalates privileges, spawns shells, or
runs any exploit payload. They only invoke standard, non-destructive
Linux enumeration commands (find, ls, systemctl, getcap, sudo -l,
crontab -l, uname) and parse their output.
"""

import subprocess
import shlex


def run_cmd(cmd, timeout=30):
    """
    Run a shell command safely and return (stdout, stderr, returncode).
    Never raises on non-zero exit -- callers should check returncode.
    Never uses shell=True.
    """
    try:
        args = cmd if isinstance(cmd, list) else shlex.split(cmd)
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"command not found: {cmd}", 127
    except subprocess.TimeoutExpired:
        return "", f"command timed out after {timeout}s: {cmd}", 124
    except Exception as e:  # defensive catch-all so one module can't crash the run
        return "", str(e), 1


class Finding:
    """A single normalized finding emitted by any scanner module."""

    SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def __init__(self, module, title, detail, severity="INFO",
                 exploitability="Unknown", mitigation="", confidence="Confirmed"):
        assert severity in self.SEVERITY_LEVELS, f"bad severity: {severity}"
        self.module = module
        self.title = title
        self.detail = detail
        self.severity = severity
        self.exploitability = exploitability
        self.mitigation = mitigation
        self.confidence = confidence

    def to_dict(self):
        return {
            "module": self.module,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
            "exploitability": self.exploitability,
            "mitigation": self.mitigation,
            "confidence": self.confidence,
        }
