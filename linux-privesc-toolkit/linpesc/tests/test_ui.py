import json
import os
import tempfile
from pathlib import Path
import unittest

from app import load_report, finding_value


class TestUIHelpers(unittest.TestCase):

    def test_load_report_none(self):
        self.assertIsNone(load_report(None))

    def test_load_report_nonexistent(self):
        p = Path("nonexistent_path_report_123.json")
        self.assertIsNone(load_report(p))

    def test_load_report_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
            tf.write("this is not valid json")
            p = Path(tf.name)
        try:
            self.assertIsNone(load_report(p))
        finally:
            if p.exists():
                p.unlink()

    def test_load_report_valid(self):
        sample = {
            "generated_at": "2026-10-23T19:00:00",
            "host_context": {"user": "alice", "is_root": False},
            "summary": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 2},
            "findings": [
                {
                    "module": "suid",
                    "title": "SUID find",
                    "severity": "HIGH",
                    "confidence": "Preliminary",
                }
            ],
        }
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tf:
            json.dump(sample, tf)
            p = Path(tf.name)
        try:
            loaded = load_report(p)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["summary"]["HIGH"], 1)
            self.assertEqual(len(loaded["findings"]), 1)
        finally:
            if p.exists():
                p.unlink()

    def test_finding_value_fallback(self):
        item = {"module": "suid", "title": "Test Title"}
        self.assertEqual(finding_value(item, "title", default="def"), "Test Title")
        self.assertEqual(finding_value(item, "nonexistent", "fallback", default="my_fallback"), "my_fallback")


if __name__ == "__main__":
    unittest.main()
