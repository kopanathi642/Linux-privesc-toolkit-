import os
import tempfile
import unittest
from unittest.mock import patch

from modules import suid_scan, kernel_scan, services, cron_scan, permissions


class TestModules(unittest.TestCase):

    # --- SUID Scan tests ---
    @patch("modules.suid_scan.run_cmd")
    def test_suid_scan_detection(self, mock_cmd):
        # find command returns /usr/bin/find and /bin/mount
        # getcap returns 127
        mock_cmd.side_effect = [
            ("/usr/bin/find\n/bin/mount", "", 0),
            ("", "command not found: getcap", 127),
        ]
        context = {}
        findings = suid_scan.scan(context)
        self.assertEqual(context["suid_binaries"], ["/usr/bin/find", "/bin/mount"])

        titles = [f.title for f in findings]
        self.assertTrue(any("Potential GTFOBins SUID match" in t for t in titles))
        self.assertTrue(any("Linux file capabilities check" in t for t in titles))

        high_finding = next(f for f in findings if "Potential GTFOBins" in f.title)
        self.assertEqual(high_finding.severity, "HIGH")
        self.assertIn("Preliminary", high_finding.confidence)

    # --- Kernel Scan tests ---
    def test_kernel_version_parsing(self):
        self.assertEqual(kernel_scan._parse_version("5.10.0-8-amd64"), (5, 10, 0))
        self.assertEqual(kernel_scan._parse_version("6.1.0"), (6, 1, 0))
        self.assertIsNone(kernel_scan._parse_version("invalid-version"))

    @patch("modules.kernel_scan.run_cmd")
    def test_kernel_dirty_pipe_match(self, mock_cmd):
        # Kernel 5.10.0 falls in Dirty Pipe range [5.8.0, 5.16.11)
        # pkexec missing
        mock_cmd.side_effect = [
            ("5.10.0-8-amd64", "", 0),
            ("", "", 1),
        ]
        context = {}
        findings = kernel_scan.scan(context)
        cve_findings = [f for f in findings if "CVE-2022-0847" in f.title]
        self.assertEqual(len(cve_findings), 1)
        self.assertEqual(cve_findings[0].severity, "HIGH")
        self.assertIn("Preliminary", cve_findings[0].confidence)

    @patch("modules.kernel_scan.run_cmd")
    def test_kernel_modern_no_dirty_pipe(self, mock_cmd):
        # Kernel 6.8.0 should NOT match Dirty Pipe
        # pkexec found
        mock_cmd.side_effect = [
            ("6.8.0-31-generic", "", 0),
            ("/usr/bin/pkexec", "", 0),
            ("pkexec version 1.05", "", 0),
        ]
        context = {}
        findings = kernel_scan.scan(context)
        dirty_pipe = [f for f in findings if "CVE-2022-0847" in f.title]
        self.assertEqual(len(dirty_pipe), 0)

        # Ensure PwnKit is evaluated as polkit check, not kernel match
        pwnkit = [f for f in findings if "pkexec" in f.title]
        self.assertTrue(len(pwnkit) > 0)
        self.assertEqual(pwnkit[0].severity, "LOW")

    # --- Services Unit tests ---
    def test_clean_exec_target(self):
        self.assertEqual(services._clean_exec_target("-/usr/bin/daemon -d"), "/usr/bin/daemon")
        self.assertEqual(services._clean_exec_target("+/usr/local/bin/run"), "/usr/local/bin/run")
        self.assertEqual(services._clean_exec_target("!/bin/sh /path/to/script"), "/bin/sh")

    def test_parse_unit_file_with_comments(self):
        content = """
        [Unit]
        Description=Test Service

        [Service]
        # User=root
        ; User=nobody
        User=customuser
        # ExecStart=/bin/false
        ExecStart=-/usr/bin/real-daemon --flag
        """
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".service") as tf:
            tf.write(content)
            temp_path = tf.name

        try:
            user, targets = services._parse_unit_file(temp_path)
            self.assertEqual(user, "customuser")
            self.assertEqual(targets, ["/usr/bin/real-daemon"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # --- Cron Scan tests ---
    def test_cron_env_or_comment(self):
        self.assertTrue(cron_scan._is_env_or_comment("# This is a comment"))
        self.assertTrue(cron_scan._is_env_or_comment("PATH=/usr/bin:/bin"))
        self.assertTrue(cron_scan._is_env_or_comment("SHELL=/bin/bash"))
        self.assertFalse(cron_scan._is_env_or_comment("0 0 * * * root /bin/backup.sh"))

    def test_cron_parse_script_targets(self):
        toks = ["/usr/bin/python3", "/opt/scripts/backup.py", "--quiet"]
        targets = cron_scan._parse_script_targets(toks)
        self.assertEqual(targets, ["/opt/scripts/backup.py"])

        toks2 = ["/bin/sh", "-c", "/usr/local/bin/cleanup.sh"]
        targets2 = cron_scan._parse_script_targets(toks2)
        self.assertEqual(targets2, ["/usr/local/bin/cleanup.sh"])

        toks3 = ["relative_cmd", "arg1"]
        targets3 = cron_scan._parse_script_targets(toks3)
        self.assertEqual(targets3, ["relative_cmd"])

    # --- Permissions tests ---
    def test_permissions_is_excluded(self):
        self.assertTrue(permissions._is_excluded("/proc/1/stat"))
        self.assertTrue(permissions._is_excluded("/sys/kernel/security"))
        self.assertTrue(permissions._is_excluded("/dev/null"))
        self.assertFalse(permissions._is_excluded("/etc/passwd"))
        self.assertFalse(permissions._is_excluded("/home/user/script.sh"))


if __name__ == "__main__":
    unittest.main()
