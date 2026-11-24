#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "test" / "check_ssr_proto_drift.py"


class SchemaDriftTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="ssr-proto-")
        self.source = Path(self.tempdir.name)
        for name in ("bfd.proto", "ip.proto"):
            shutil.copyfile(ROOT / "files" / name, self.source / name)

    def tearDown(self):
        self.tempdir.cleanup()

    def run_checker(self):
        environment = os.environ.copy()
        environment["SSR_PROTO_DIR"] = str(self.source)
        return subprocess.run(
            [sys.executable, str(CHECKER)],
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_comment_changes_do_not_report_schema_drift(self):
        bfd_path = self.source / "bfd.proto"
        bfd_path.write_text("// local comment\n" + bfd_path.read_text(encoding="utf-8"),
                            encoding="utf-8")
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_field_changes_fail_schema_drift_check(self):
        bfd_path = self.source / "bfd.proto"
        schema = bfd_path.read_text(encoding="utf-8")
        bfd_path.write_text(schema.replace("metadata_key_index = 5", "metadata_key_index = 6"),
                            encoding="utf-8")
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Schema drift detected: bfd.proto", result.stderr)


if __name__ == "__main__":
    unittest.main()
