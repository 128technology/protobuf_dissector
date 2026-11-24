#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

import os
import subprocess
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "test" / "svr" / "real"
REKEY_CAPTURE = REAL / "svr2_eskm_7.2.5_wan_data_bfd_rekey.pcap"
ESKM_CAPTURE = REAL / "eskm_initial_key_exchange.pcap"


@unittest.skipUnless(REKEY_CAPTURE.is_file(), "real SVR rekey capture is not present")
class RealSvrCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tshark_executable = os.environ.get("TSHARK", "tshark")

    def run_tshark(self, *args):
        result = subprocess.run(
            [
                self.tshark_executable,
                "-X",
                "lua_script:" + str(ROOT / "protobuf.lua"),
                "-r",
                str(REKEY_CAPTURE),
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return [
            line for line in result.stdout.splitlines() if line != "AST modules loaded"
        ]

    def test_svr_metadata_and_cached_data_are_recognized(self):
        self.assertEqual(len(self.run_tshark("-Y", "svr", "-T", "fields", "-e", "frame.number")), 19049)

    def test_eskm_rekey_index_matches_svr2_metadata(self):
        rows = self.run_tshark(
            "-Y",
            "frame.number == 7744",
            "-T",
            "fields",
            "-e",
            "svr.eskm.rekey_index",
            "-e",
            "svr.eskm_key_index",
            "-e",
            "_ws.col.Info",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].split("\t")[:2], ["209", "209"])
        self.assertIn("ESKM key=209 SVR key=209", rows[0])

    def test_svr_layout_and_hmac_lengths_match_udp_payloads(self):
        rows = self.run_tshark(
            "-o",
            "svr.hmac_enabled:TRUE",
            "-o",
            "svr.hmac_length:16",
            "-Y",
            "svr",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=a",
            "-e",
            "udp.length",
            "-e",
            "svr.hdr_len",
            "-e",
            "svr.payload_len",
            "-e",
            "svr.hmac",
            "-e",
            "svr.encrypted_metadata",
            "-e",
            "svr.opaque_payload",
            "-e",
            "svr.tlv.type",
        )
        self.assertEqual(len(rows), 19049)
        tlv_sequences = Counter()
        inner_lengths = Counter()
        metadata_packets = 0

        for row in rows:
            fields = row.split("\t")
            udp_payload_length = int(fields[0]) - 8
            hmac_length = len(fields[3].split()) if fields[3] else 0
            opaque_length = len(fields[5].split()) if fields[5] else 0
            self.assertEqual(hmac_length, 16)

            if fields[1]:
                metadata_packets += 1
                metadata_length = int(fields[2])
                encrypted_metadata_length = len(fields[4].split()) if fields[4] else 0
                self.assertEqual(encrypted_metadata_length, metadata_length)
                inner_length = udp_payload_length - int(fields[1]) - metadata_length - hmac_length
                self.assertGreaterEqual(inner_length, 0)
                self.assertEqual(inner_length, opaque_length)
                tlv_sequences[tuple(fields[6].split(","))] += 1
                inner_lengths[inner_length] += 1
            else:
                self.assertEqual(udp_payload_length, hmac_length + opaque_length)
                inner_lengths[opaque_length] += 1

        self.assertEqual(metadata_packets, 23)
        self.assertEqual(
            tlv_sequences,
            Counter({("16", "49"): 21, ("16", "18", "49"): 1, ("16",): 1}),
        )
        self.assertEqual(inner_lengths, Counter({112: 19048, 0: 1}))


@unittest.skipUnless(ESKM_CAPTURE.is_file(), "initial ESKM capture is not present")
class RealEskmCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tshark_executable = os.environ.get("TSHARK", "tshark")

    def run_tshark(self, *args):
        result = subprocess.run(
            [
                self.tshark_executable,
                "-X",
                "lua_script:" + str(ROOT / "protobuf.lua"),
                "-r",
                str(ESKM_CAPTURE),
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return [
            line for line in result.stdout.splitlines() if line != "AST modules loaded"
        ]

    def test_initial_key_exchange_decodes_without_protobuf_errors(self):
        decoded = self.run_tshark("-Y", "ssr_bfd", "-T", "fields", "-e", "_ws.col.Info")
        errors = self.run_tshark(
            "-Y", "ssr_bfd.metadata_error", "-T", "fields", "-e", "frame.number"
        )
        self.assertEqual(len(decoded), 5)
        self.assertEqual(errors, [])
        self.assertTrue(any("CERT" in row for row in decoded))
        self.assertTrue(any("CERT ACK" in row for row in decoded))
        self.assertTrue(any("PUB_DH_KEY" in row for row in decoded))

    def test_saturated_bfd_length_is_reported_without_decode_errors(self):
        saturated = self.run_tshark(
            "-Y",
            "ssr_bfd.saturated_length",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        errors = self.run_tshark(
            "-Y",
            "ssr_bfd.metadata_error",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        self.assertTrue(saturated)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
