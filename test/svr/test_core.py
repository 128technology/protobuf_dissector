#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COOKIE = bytes.fromhex("4c48dbc6ddf6670c")


def tlv(tlv_type, value):
    return struct.pack("!HH", tlv_type, len(value)) + value


def varint(value):
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def zero_tlvs(tlv_types):
    fixed_lengths = {
        1: 10, 2: 13, 3: 37, 4: 13, 5: 37, 6: 16, 8: 4, 9: 4,
        11: 0, 12: 0, 13: 8, 16: 4, 18: 0, 20: 4, 21: 16,
        24: 1, 25: 6, 26: 10, 27: 12, 28: 2, 31: 8, 32: 0,
        34: 1, 39: 4, 40: 0, 42: 4, 43: 0, 44: 1, 45: 4,
        46: 1, 47: 0, 48: 5, 49: 2, 51: 7, 52: 19,
    }
    return b"".join(
        tlv(tlv_type, bytes(4 if tlv_type == 23 else fixed_lengths.get(tlv_type, 0)))
        for tlv_type in tlv_types
    )


def svr_packet(header_tlvs=b"", payload_tlvs=b"", version=1, declared_header=None,
               declared_payload=None, inner_payload=b""):
    header_length = 12 + len(header_tlvs) if declared_header is None else declared_header
    payload_length = len(payload_tlvs) if declared_payload is None else declared_payload
    version_and_header_length = (version << 12) | header_length
    return (
        COOKIE
        + struct.pack("!HH", version_and_header_length, payload_length)
        + header_tlvs
        + payload_tlvs
        + inner_payload
    )


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_udp(payload, source_port, destination_port):
    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    source = bytes((192, 0, 2, 1))
    destination = bytes((198, 51, 100, 2))
    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        17,
        0,
        source,
        destination,
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    return ip_header + udp_header + payload


def write_pcap(path, packets):
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, packet in enumerate(packets, 1):
            capture.write(struct.pack("<IIII", index, 0, len(packet), len(packet)))
            capture.write(packet)


class SvrDissectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tshark_executable = os.environ.get("TSHARK", "tshark")
        cls.tempdir = tempfile.TemporaryDirectory(prefix="svr-dissector-")
        cls.capture = Path(cls.tempdir.name) / "svr_core.pcap"

        valid_header = tlv(16, struct.pack("!I", 7)) + tlv(49, bytes((208, 1)))
        wrong_fixed_length = tlv(16, b"\x00\x00\x07")
        unknown_type = tlv(999, b"")
        overrun_tlv = struct.pack("!HH", 16, 5)
        wrong_section = tlv(16, struct.pack("!I", 7))
        session_key = tlv(
            2,
            struct.pack(
                "!4s4sHHB",
                bytes((192, 0, 2, 10)),
                bytes((198, 51, 100, 53)),
                12345,
                53,
                17,
            ),
        )
        dns_query = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        key_data = b"\x08\x03\x28" + varint(209)
        bfd_metadata = b"\x22" + varint(len(key_data)) + key_data
        bfd_packet = bytes((0x20, 0, 0, 24 + len(bfd_metadata))) + bytes(20) + bfd_metadata
        ack_data = key_data + b"\x30\x01"
        ack_metadata = b"\x22" + varint(len(ack_data)) + ack_data
        ack_packet = bytes((0x20, 0, 0, 24 + len(ack_metadata))) + bytes(20) + ack_metadata
        ack_only_data = b"\x28" + varint(209) + b"\x30\x01"
        ack_only_metadata = b"\x22" + varint(len(ack_only_data)) + ack_only_data
        ack_only_packet = (
            bytes((0x20, 0, 0, 24 + len(ack_only_metadata)))
            + bytes(20)
            + ack_only_metadata
        )
        echo_data = b"\x0a\x02\x08\x01\x18\x01\x20\x01"
        echo_metadata = b"\x12" + varint(len(echo_data)) + echo_data
        echo_packet = bytes((0x20, 0, 0, 24 + len(echo_metadata))) + bytes(20) + echo_metadata
        auth_packet = bytes((0x20, 0x04, 0, 26)) + bytes(20) + b"\x01\x02"
        mlkem_key = b"\x0a\x06\x0a\x02\xaa\xbb\x12\x00"
        mlkem_data = b"\x08\x04\x3a" + varint(len(mlkem_key)) + mlkem_key
        mlkem_metadata = b"\x22" + varint(len(mlkem_data)) + mlkem_data
        mlkem_packet = bytes((0x20, 0, 0, 24 + len(mlkem_metadata))) + bytes(20) + mlkem_metadata
        header_types = (1, 16, 18, 20, 21, 23, 24, 26, 28, 39, 40, 45, 46, 48, 49)
        payload_types = tuple(tlv_type for tlv_type in range(1, 53) if tlv_type not in header_types)
        all_header_tlvs = zero_tlvs(header_types)
        all_payload_tlvs = zero_tlvs(payload_types)
        waypoint_svr = svr_packet(
            header_tlvs=tlv(45, struct.pack("!HH", 1280, 1280)),
            inner_payload=bfd_packet,
        )
        svr_rekey = svr_packet(tlv(49, bytes((209, 1))))
        svr_mismatched_rekey = svr_packet(tlv(49, bytes((208, 1))))
        bad_cookie = b"\x00" + svr_packet()[1:]
        packets = [
            svr_packet(valid_header, inner_payload=b"DATA" + b"H" * 16),
            b"FOLLOWUP",
            svr_packet(version=2),
            svr_packet(declared_header=11),
            svr_packet(declared_payload=8),
            svr_packet(wrong_fixed_length),
            svr_packet(unknown_type),
            svr_packet(overrun_tlv, declared_header=16),
            svr_packet(payload_tlvs=wrong_section),
            svr_packet(payload_tlvs=session_key, inner_payload=dns_query),
        ]
        packets = [
            ipv4_udp(packet, 40001 if index < 2 else 40000 + index, 40001)
            for index, packet in enumerate(packets)
        ]
        packets.extend([
            ipv4_udp(bfd_packet, 1280, 1280),
            ipv4_udp(ack_packet, 1280, 1280),
            ipv4_udp(svr_rekey, 16400, 16403),
            ipv4_udp(svr_mismatched_rekey, 16400, 16403),
            ipv4_udp(bad_cookie, 40014, 40001),
            ipv4_udp(echo_packet, 1280, 1280),
            ipv4_udp(ack_only_packet, 1280, 1280),
            ipv4_udp(auth_packet, 1280, 1280),
            ipv4_udp(mlkem_packet, 1280, 1280),
            ipv4_udp(svr_packet(header_tlvs=all_header_tlvs), 40019, 40001),
            ipv4_udp(svr_packet(payload_tlvs=all_payload_tlvs), 40020, 40001),
            ipv4_udp(waypoint_svr, 40021, 40001),
        ])
        security_identifier = tlv(16, struct.pack("!I", 7))
        gcm_metadata_nonce = bytes.fromhex("0102030405060708090a0b0c")
        gcm_metadata = bytes.fromhex("dc20e91a") + gcm_metadata_nonce + bytes.fromhex(
            "619224516a3fb93d9ed15c4b6672e6ba"
        )
        gcm_payload_nonce = bytes.fromhex("0f0e0d0c0b0a090807060504")
        gcm_payload = bytes.fromhex("74c1052c69063081b7e5d8abcce4") + gcm_payload_nonce + bytes.fromhex(
            "6e6ce8905155ec376b2e049a0d19ccaa"
        )
        tampered_gcm_payload = bytearray(gcm_payload)
        tampered_gcm_payload[-1] ^= 1
        packets.extend([
            ipv4_udp(
                svr_packet(
                    header_tlvs=security_identifier,
                    payload_tlvs=gcm_metadata,
                    inner_payload=gcm_payload,
                ),
                16400,
                16403,
            ),
            ipv4_udp(
                svr_packet(
                    header_tlvs=security_identifier,
                    payload_tlvs=gcm_metadata,
                    inner_payload=bytes(tampered_gcm_payload),
                ),
                16400,
                16403,
            ),
        ])
        cbc_key = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
        cbc_metadata = bytes.fromhex(
            "72321e22460f81c646fb12b82467699e000102030405060708090a0b0c0d0e0f"
        )
        cbc_payload = bytes.fromhex(
            "e2cbef78078b9b67049ed986b4843466f0e0d0c0b0a090807060504030201000"
        )
        packets.append(
            ipv4_udp(
                svr_packet(
                    header_tlvs=security_identifier,
                    payload_tlvs=cbc_metadata,
                    inner_payload=cbc_payload,
                ),
                16400,
                16403,
            )
        )
        indexed_gcm_metadata = bytes.fromhex("dc20e91a") + gcm_metadata_nonce + bytes.fromhex(
            "7a124e7849bb67827437a09c8dc0bf3e"
        )
        packets.append(
            ipv4_udp(
                svr_packet(
                    header_tlvs=tlv(49, bytes((208, 1))),
                    payload_tlvs=indexed_gcm_metadata,
                    inner_payload=gcm_payload,
                ),
                16400,
                16403,
            )
        )
        write_pcap(cls.capture, packets)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def run_tshark(self, *args, plugin="protobuf.lua"):
        result = subprocess.run(
            [
                self.tshark_executable,
                "-X",
                "lua_script:" + str(ROOT / plugin),
                "-r",
                str(self.capture),
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError("tshark failed: " + result.stderr)
        return "\n".join(
            line for line in result.stdout.splitlines() if line != "AST modules loaded"
        )

    def test_valid_packet_and_svr2_indices(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 1 && svr.eskm.rekey_index == 208 && svr.svr2.payload_index == 1",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "svr.security_identifier",
        )
        self.assertEqual(output.strip(), "1\t7")

    def test_svr_plugin_loads_without_protobuf_engine(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 1 && svr.eskm.rekey_index == 208",
            "-T",
            "fields",
            "-e",
            "frame.number",
            plugin="svr.lua",
        )
        self.assertEqual(output.strip(), "1")

    def test_invalid_headers_do_not_match_heuristic(self):
        output = self.run_tshark("-Y", "svr.version == 1", "-T", "fields", "-e", "frame.number")
        self.assertEqual(
            output.strip(),
            "1\n6\n7\n8\n9\n10\n13\n14\n20\n21\n22\n23\n24\n25\n26",
        )

    def test_malformed_and_unknown_tlvs_report_experts(self):
        malformed = self.run_tshark("-Y", "svr.malformed_tlv", "-T", "fields", "-e", "frame.number")
        unknown = self.run_tshark("-Y", "svr.unknown_type", "-T", "fields", "-e", "frame.number")
        wrong_section = self.run_tshark(
            "-o",
            "svr.md_encrypted:never",
            "-Y",
            "svr.wrong_section",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        self.assertEqual(malformed.strip().splitlines(), ["6", "8"])
        self.assertEqual(unknown.strip(), "7")
        self.assertEqual(wrong_section.strip(), "9")

    def test_followup_packet_uses_cached_session(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 2 && svr.opaque_payload",
            "-T",
            "fields",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "svr.session_cache.rekey_index",
            "-e",
            "svr.session_cache.payload_index",
        )
        self.assertEqual(output.strip(), "SVR\t208\t1")

    def test_plaintext_inner_payload_uses_session_key_protocol_and_port(self):
        output = self.run_tshark(
            "-o",
            "svr.md_encrypted:never",
            "-o",
            "svr.payload_encrypted:never",
            "-Y",
            "dns.qry.name == \"example.com\"",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "dns.qry.name",
        )
        self.assertEqual(output.strip(), "10\texample.com")

    def test_bfd_eskm_key_index_matches_eskm_rekey_index(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 13 && svr.eskm_key_index == 209",
            "-T",
            "fields",
            "-e",
            "svr.eskm.rekey_index",
            "-e",
            "_ws.col.Info",
        )
        self.assertEqual(
            output.strip(),
            "209\t[SVR] SVR2 Indices=rekey=209 payload=1 ESKM key=209 SVR key=209",
        )

    def test_eskm_ack_does_not_replace_key_index_during_rotation(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 14 && svr.eskm_key_index == 209",
            "-T",
            "fields",
            "-e",
            "svr.eskm.rekey_index",
            "-e",
            "svr.eskm_key_index",
            "-e",
            "_ws.col.Info",
        )
        self.assertEqual(
            output.strip(),
            "208\t209\t[SVR] SVR2 Indices=rekey=208 payload=1 ESKM key=209 SVR key=208",
        )

    def test_bfd_echo_annotations_and_ack_only_key_metadata(self):
        echo = self.run_tshark(
            "-Y",
            "frame.number == 16",
            "-T",
            "fields",
            "-e",
            "_ws.col.Info",
        )
        ack_only = self.run_tshark(
            "-Y",
            "frame.number == 17",
            "-T",
            "fields",
            "-e",
            "_ws.col.Info",
        )
        self.assertIn("EchoRequest MTU discovery Peer traceroute", echo)
        self.assertIn("ACK-only index=209", ack_only)

    def test_bfd_authentication_is_reported(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 18 && ssr_bfd.auth_present && !ssr_bfd.invalid_header",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        self.assertEqual(output.strip(), "18")

    def test_bfd_ml_kem_key_type_is_recognized(self):
        output = self.run_tshark(
            "-Y",
            "frame.number == 19 && !ssr_bfd.metadata_error",
            "-T",
            "fields",
            "-e",
            "_ws.col.Info",
        )
        self.assertIn("ML_KEM_KEY", output)

    def test_waypoint_ports_dispatch_inner_bfd_metadata(self):
        output = self.run_tshark(
            "-o",
            "svr.payload_encrypted:never",
            "-Y",
            "frame.number == 22 && ssr_bfd.version == 1",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        self.assertEqual(output.strip(), "22")

    def test_aes_gcm_decrypts_metadata_and_inner_payload(self):
        output = self.run_tshark(
            "-o", "svr.cipher:aes-gcm",
            "-o", "svr.keys:sid:7=00000000000000000000000000000000",
            "-Y", "frame.number == 23 && svr.decrypted_metadata && svr.inner_payload",
            "-T", "fields",
            "-e", "frame.number",
        )
        self.assertEqual(output.strip(), "23")

    def test_aes_gcm_rejects_tampered_payload_and_keeps_metadata(self):
        output = self.run_tshark(
            "-o", "svr.cipher:aes-gcm",
            "-o", "svr.keys:sid:7=00000000000000000000000000000000",
            "-Y", "frame.number == 24 && svr.decrypted_metadata && svr.decryption_failed",
            "-T", "fields",
            "-e", "frame.number",
        )
        self.assertEqual(output.strip(), "24")

    def test_aes_cbc_decrypts_ssr_padding_and_reports_no_authentication(self):
        output = self.run_tshark(
            "-o", "svr.cipher:aes-cbc",
            "-o", "svr.keys:sid:7=101112131415161718191a1b1c1d1e1f",
            "-Y", "frame.number == 25 && svr.decrypted_metadata && svr.inner_payload",
            "-T", "fields",
            "-e", "frame.number",
        )
        self.assertEqual(output.strip(), "25")

    def test_svr2_rekey_and_payload_indices_select_gcm_keys(self):
        output = self.run_tshark(
            "-o", "svr.cipher:aes-gcm",
            "-o", "svr.keys:rekey:208=00000000000000000000000000000000;payload:1=00000000000000000000000000000000",
            "-Y", "frame.number == 26 && svr.decrypted_metadata && svr.inner_payload",
            "-T", "fields",
            "-e", "frame.number",
        )
        self.assertEqual(output.strip(), "26")

    def test_encrypted_metadata_stays_opaque_without_matching_key(self):
        output = self.run_tshark(
            "-Y", "frame.number == 23 && svr.encrypted_metadata && !svr.decrypted_metadata",
            "-T", "fields",
            "-e", "frame.number",
        )
        self.assertEqual(output.strip(), "23")

    def test_all_known_tlvs_decode_in_expected_sections(self):
        header_count = self.run_tshark(
            "-Y",
            "frame.number == 20",
            "-T",
            "fields",
            "-E",
            "occurrence=a",
            "-e",
            "svr.tlv.type",
        )
        payload_count = self.run_tshark(
            "-Y",
            "frame.number == 21",
            "-T",
            "fields",
            "-E",
            "occurrence=a",
            "-e",
            "svr.tlv.type",
        )
        diagnostics = self.run_tshark(
            "-Y",
            "(frame.number == 20 || frame.number == 21) && "
            "(svr.unknown_type || svr.malformed_tlv || svr.wrong_section)",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        self.assertEqual(len(header_count.strip().split(",")), 15)
        self.assertEqual(len(payload_count.strip().split(",")), 37)
        self.assertEqual(diagnostics.strip(), "")

    def test_configured_hmac_is_split_from_inner_payload(self):
        output = self.run_tshark(
            "-o",
            "svr.hmac_enabled:TRUE",
            "-o",
            "svr.hmac_length:16",
            "-Y",
            "frame.number == 1",
            "-T",
            "fields",
            "-e",
            "svr.hmac",
        )
        self.assertEqual(output.strip(), " ".join(["48"] * 16))


if __name__ == "__main__":
    unittest.main()
