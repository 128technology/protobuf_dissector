#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "test" / "svr" / "gen_svr_pcaps.py"


class SyntheticCaptureGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tshark = os.environ.get("TSHARK", "tshark")
        cls.tempdir = tempfile.TemporaryDirectory(prefix="svr-matrix-")
        cls.capture = Path(cls.tempdir.name) / "svr_matrix.pcap"
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--output", str(cls.capture)],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError("pcap generation failed: " + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def run_tshark(self, *args):
        result = subprocess.run(
            [
                self.tshark,
                "-X",
                "lua_script:" + str(ROOT / "protobuf.lua"),
                "-r",
                str(self.capture),
                *args,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError("tshark failed: " + result.stderr)
        return [
            line for line in result.stdout.splitlines()
            if line != "AST modules loaded"
        ]

    def test_pcap_records_are_complete_and_deterministic(self):
        data = self.capture.read_bytes()
        self.assertEqual(struct.unpack_from("<I", data)[0], 0xA1B2C3D4)
        offset = 24
        packet_count = 0
        while offset < len(data):
            self.assertGreaterEqual(len(data) - offset, 16)
            captured_length = struct.unpack_from("<I", data, offset + 8)[0]
            offset += 16 + captured_length
            self.assertLessEqual(offset, len(data))
            packet_count += 1
        self.assertEqual(offset, len(data))
        self.assertGreaterEqual(packet_count, 30)

    def test_generated_matrix_exercises_svr_bfd_and_malformed_cases(self):
        tlv_52 = self.run_tshark(
            "-Y", "svr.tlv.type == 52", "-T", "fields", "-e", "frame.number"
        )
        saturated = self.run_tshark(
            "-Y", "ssr_bfd.saturated_length && !ssr_bfd.metadata_error",
            "-T", "fields", "-e", "frame.number",
        )
        malformed = self.run_tshark(
            "-Y", "svr.malformed_tlv || svr.unknown_type",
            "-T", "fields", "-e", "frame.number",
        )
        self.assertTrue(tlv_52)
        self.assertTrue(saturated)
        self.assertGreaterEqual(len(malformed), 2)

    def test_outer_tcp_and_supported_hmac_trailer_lengths(self):
        tcp_svr = self.run_tshark(
            "-Y", "tcp && svr", "-T", "fields", "-e", "frame.number"
        )
        self.assertEqual(len(tcp_svr), 1)

        for offset, digest_length in enumerate((16, 20, 32, 48, 64), start=3):
            output = self.run_tshark(
                "-o", "svr.hmac_enabled:TRUE",
                "-o", "svr.hmac_length:{}".format(digest_length),
                "-Y", "frame.number == {}".format(offset),
                "-T", "fields",
                "-e", "svr.hmac",
            )
            self.assertEqual(len(output), 1)
            self.assertEqual(len(output[0].split()), digest_length)

    def test_personal_plugin_loader_requires_path_and_decodes_packets(self):
        home = Path(self.tempdir.name) / "wireshark-profile"
        environment = os.environ.copy()
        if os.name == "nt":
            environment["APPDATA"] = str(home)
            environment["USERPROFILE"] = str(home)
            plugin_dir = home / "Wireshark" / "plugins"
        else:
            environment["HOME"] = str(home)
            environment["XDG_CONFIG_HOME"] = str(home / ".config")
            plugin_dir = home / ".local" / "lib" / "wireshark" / "plugins"
        plugin_dir.mkdir(parents=True)

        loader_source = (ROOT / "svr_loader.lua").read_text(encoding="utf-8")
        installed_loader = plugin_dir / "svr_loader.lua"
        installed_loader.write_text(loader_source, encoding="utf-8")
        unconfigured = subprocess.run(
            [self.tshark, "-r", str(self.capture), "-T", "fields", "-e", "frame.number"],
            env=environment, capture_output=True, text=True,
        )
        self.assertIn("Set protobuf_file in svr_loader.lua", unconfigured.stderr)

        placeholder = 'local protobuf_file = ""'
        self.assertEqual(loader_source.count(placeholder), 1)
        path = json.dumps((ROOT / "protobuf.lua").as_posix(), ensure_ascii=False)
        installed_loader.write_text(
            loader_source.replace(placeholder, "local protobuf_file = " + path),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                self.tshark, "-r", str(self.capture), "-Y", "svr || ssr_bfd",
                "-T", "fields", "-e", "_ws.col.Protocol",
            ],
            env=environment, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Lua: Error", result.stderr)
        self.assertIn("SVR", result.stdout.splitlines())
        self.assertIn("SSR BFD", result.stdout.splitlines())

    def test_synthetic_packet_summaries_match_golden_output(self):
        output = self.run_tshark(
            "-Y",
            "frame.number >= 11 && frame.number <= 23",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
        )
        expected = (
            ROOT / "test" / "svr" / "expected" / "matrix_summaries.tsv"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(output, expected)


if __name__ == "__main__":
    unittest.main()
