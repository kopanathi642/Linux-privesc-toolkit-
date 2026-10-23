import json
import os
import tempfile
import unittest

from modules.utils import Finding
from modules import report


class TestReport(unittest.TestCase):

    def setUp(self):
        self.findings = [
            Finding(module="permissions", title="World writable file", detail="/etc/test", severity="MEDIUM", confidence="Confirmed"),
            Finding(module="services", title="ExecStart writable", detail="/usr/bin/job", severity="CRITICAL", confidence="Confirmed"),
            Finding(module="sysinfo", title="Host identity", detail="user=test", severity="INFO", confidence="Confirmed"),
            Finding(module="suid_scan", title="SUID find match", detail="/usr/bin/find", severity="HIGH", confidence="Preliminary"),
            Finding(module="cron_scan", title="Relative path cron", detail="run.sh", severity="LOW", confidence="Preliminary"),
        ]
        self.context = {
            "user": "testuser",
            "id": "uid=1000(testuser)",
            "kernel": "Linux 6.8.0-test",
            "is_root": False,
        }

    def test_summarize_counts(self):
        counts = report.summarize(self.findings)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["INFO"], 1)

    def test_sorted_findings_order(self):
        sorted_f = report._sorted_findings(self.findings)
        severities = [f.severity for f in sorted_f]
        self.assertEqual(severities, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    def test_to_json_valid_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "report.json")
            res_path = report.to_json(self.findings, self.context, out_file)
            self.assertTrue(os.path.exists(res_path))

            with open(res_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("generated_at", data)
            self.assertIn("host_context", data)
            self.assertIn("summary", data)
            self.assertIn("findings", data)

            self.assertEqual(data["host_context"]["user"], "testuser")
            self.assertEqual(len(data["findings"]), 5)
            # Check confidence serialized
            self.assertEqual(data["findings"][0]["severity"], "CRITICAL")
            self.assertEqual(data["findings"][0]["confidence"], "Confirmed")

    def test_to_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "report.txt")
            res_path = report.to_text(self.findings, self.context, out_file)
            self.assertTrue(os.path.exists(res_path))

            with open(res_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("CRITICAL", content)
            self.assertIn("testuser", content)
            self.assertIn("ExecStart writable", content)

    def test_to_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "report.html")
            res_path = report.to_html(self.findings, self.context, out_file)
            self.assertTrue(os.path.exists(res_path))

            with open(res_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("testuser", content)
            self.assertIn("badge", content)
            self.assertIn("Confidence:", content)


if __name__ == "__main__":
    unittest.main()
