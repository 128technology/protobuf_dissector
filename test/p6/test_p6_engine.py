#!/usr/bin/env python3
#
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.
#
# Focused regression tests for the Phase 6 protobuf-engine additions:
# proto3 syntax (incl. implicit/label-less fields), packed scalar decoding
# (both proto2 "[packed=true]" and proto3's implicit packed-by-default
# repeated scalars), map fields (scalar- and message-valued), and TCP
# framing ("length32" and "varint" modes).
#
# This file is intentionally separate from test/svr/*.py and is also run
# by test/run_tests.sh; run it directly, e.g.:
#
#   TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark \
#       python3 test/p6/test_p6_engine.py -v
#
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = Path(__file__).resolve().parent


def varint(value):
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def tag(field_num, wtype):
    return varint((field_num << 3) | wtype)


def length_delimited(field_num, data):
    return tag(field_num, 2) + varint(len(data)) + data


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
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 17, 0, source, destination,
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    return ip_header + udp_header + payload


def ipv4_tcp(payload, source_port, destination_port, seq=1, ack=1, flags=0x18):
    tcp_header = struct.pack(
        "!HHIIBBHHH", source_port, destination_port, seq, ack, 5 << 4, flags, 65535, 0, 0,
    )
    source = bytes((192, 0, 2, 1))
    destination = bytes((198, 51, 100, 2))
    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0, source, destination,
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    return ip_header + tcp_header + payload


def write_pcap(path, packets):
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, packet in enumerate(packets, 1):
            capture.write(struct.pack("<IIII", index, 0, len(packet), len(packet)))
            capture.write(packet)


class P6EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tshark_executable = os.environ.get("TSHARK", "tshark")
        cls.tmpdir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def run_tshark(self, pcap_path, proto_file, *args):
        result = subprocess.run(
            [
                self.tshark_executable,
                "-r", str(pcap_path),
                "-X", "lua_script:" + str(ROOT / "protobuf.lua"),
                "-X", "lua_script1:" + str(proto_file),
                *args,
                "-V",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError("tshark failed: " + result.stderr)
        return result.stdout

    def write_pcap(self, name, packets):
        path = Path(self.tmpdir.name) / name
        write_pcap(path, packets)
        return path

    def test_proto3_packed_and_map_fields(self):
        packed_values = b"".join(varint(v) for v in (1, 2, 300, 4))
        values_field = length_delimited(1, packed_values)

        def map_entry_str(key, value):
            return length_delimited(1, key.encode()) + length_delimited(2, value.encode())

        attrs_field = length_delimited(2, map_entry_str("color", "red"))

        def map_entry_int_nested(key, nested_name):
            nested = length_delimited(1, nested_name.encode())
            return tag(1, 0) + varint(key) + length_delimited(2, nested)

        items_field = length_delimited(3, map_entry_int_nested(10, "alpha"))
        label_field = length_delimited(4, b"hello-p6")

        payload = values_field + attrs_field + items_field + label_field
        packet = ipv4_udp(payload, 40000, 40001)
        pcap_path = self.write_pcap("sample.pcap", [packet])

        output = self.run_tshark(
            pcap_path, TEST_DIR / "p6_test.proto",
            "-d", "udp.port==40001,p6test.sample",
        )

        # packed repeated scalar: all four values decoded from one blob
        self.assertIn("values: 1", output)
        self.assertIn("values: 2", output)
        self.assertIn("values: 300", output)
        self.assertIn("values: 4", output)

        # scalar-valued map field
        self.assertIn("AttrsEntry", output)
        self.assertIn("key: color", output)
        self.assertIn("value: red", output)

        # message-valued map field (nested message resolved through the map)
        self.assertIn("ItemsEntry", output)
        self.assertIn("key: 10", output)
        self.assertIn("Nested", output)
        self.assertIn("name: alpha", output)

        # proto3 implicit (label-less) singular field
        self.assertIn("label: hello-p6", output)

    def test_proto2_explicit_packed_option(self):
        payload = length_delimited(1, b"".join(varint(v) for v in (5, 6, 700)))
        packet = ipv4_udp(payload, 40002, 40003)
        pcap_path = self.write_pcap("sample2.pcap", [packet])

        output = self.run_tshark(
            pcap_path, TEST_DIR / "p6_packed2.proto",
            "-d", "udp.port==40003,p6test2.sample2",
        )

        self.assertIn("values: 5", output)
        self.assertIn("values: 6", output)
        self.assertIn("values: 700", output)

    def test_proto2_defaults_are_generated_only_when_fields_are_absent(self):
        packet = ipv4_udp(tag(5, 0) + varint(12), 40005, 40006)
        pcap_path = self.write_pcap("defaults.pcap", [packet])
        output = self.run_tshark(
            pcap_path, TEST_DIR / "defaults.proto",
            "-d", "udp.port==40006,p6defaults.defaults",
        )

        self.assertIn("count: 7", output)
        self.assertIn("label: fallback", output)
        self.assertIn("enabled: False", output)
        self.assertIn("color: BLUE", output)
        self.assertIn("present: 12", output)
        self.assertIn("signed: -3", output)
        self.assertIn("raw: 4142", output)
        self.assertNotIn("present: 9", output)

    def test_weak_import_loads_existing_file(self):
        packet = ipv4_udp(length_delimited(1, b"weak-import"), 40007, 40008)
        pcap_path = self.write_pcap("weak_import.pcap", [packet])
        output = self.run_tshark(
            pcap_path, TEST_DIR / "weak_import.proto",
            "-d", "udp.port==40008,p6weak.sample",
        )
        self.assertIn("value: weak-import", output)

    def test_missing_weak_import_fails_explicitly(self):
        packet = ipv4_udp(length_delimited(1, b"missing"), 40009, 40010)
        pcap_path = self.write_pcap("missing_weak_import.pcap", [packet])
        result = subprocess.run(
            [
                self.tshark_executable,
                "-r", str(pcap_path),
                "-X", "lua_script:" + str(ROOT / "protobuf.lua"),
                "-X", "lua_script1:" + str(TEST_DIR / "missing_weak_import.proto"),
                "-d", "udp.port==40010,p6weakmissing.sample",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not_present.proto", result.stderr)

    def test_doxygen_field_tags_set_display_name_and_description(self):
        packet = ipv4_udp(length_delimited(1, b"documented"), 40011, 40012)
        pcap_path = self.write_pcap("doc_comments.pcap", [packet])
        output = self.run_tshark(
            pcap_path, TEST_DIR / "doc_comments.proto",
            "-d", "udp.port==40012,p6docs.sample",
        )
        self.assertIn("Friendly label: documented", output)

        result = subprocess.run(
            [
                self.tshark_executable,
                "-G", "fields",
                "-X", "lua_script:" + str(ROOT / "protobuf.lua"),
                "-X", "lua_script1:" + str(TEST_DIR / "doc_comments.proto"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(
            result.stdout,
            r"(?m)^F\tFriendly label\tp6docs\.sample\.label\t.*Human-readable value displayed in packet tree",
        )

    def test_plugin_reload_recompiles_modules_without_duplicate_registration(self):
        packet = ipv4_udp(b"reload", 40013, 40014)
        pcap_path = self.write_pcap("reload.pcap", [packet])
        result = subprocess.run(
            [
                self.tshark_executable,
                "-r", str(pcap_path),
                "-X", "lua_script:" + str(ROOT / "protobuf.lua"),
                "-X", "lua_script:" + str(ROOT / "protobuf.lua"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("AST modules loaded"), 2)

    def test_tcp_length32_framing_reassembles_split_messages(self):
        msg1 = length_delimited(4, b"hello-p6")
        msg2 = length_delimited(4, b"second-message")

        def framed(msg):
            return struct.pack("!I", len(msg)) + msg

        stream = framed(msg1) + framed(msg2)
        split_point = len(framed(msg1)) + 3
        seg1, seg2 = stream[:split_point], stream[split_point:]

        pkt1 = ipv4_tcp(seg1, 55001, 50002, seq=1)
        pkt2 = ipv4_tcp(seg2, 55001, 50002, seq=1 + len(seg1))
        pcap_path = self.write_pcap("tcp_framing.pcap", [pkt1, pkt2])

        output = self.run_tshark(
            pcap_path, TEST_DIR / "p6_test.proto",
            "-d", "tcp.port==50002,p6test.sample",
            "-o", "p6test.sample.tcp_framing:length32",
        )

        self.assertIn("label: hello-p6", output)
        self.assertIn("label: second-message", output)

    def test_tcp_varint_framing(self):
        msg1 = length_delimited(4, b"hello-p6")
        msg2 = length_delimited(4, b"second-message")

        def framed(msg):
            return varint(len(msg)) + msg

        stream = framed(msg1) + framed(msg2)
        packet = ipv4_tcp(stream, 55003, 50004, seq=1)
        pcap_path = self.write_pcap("tcp_varint.pcap", [packet])

        output = self.run_tshark(
            pcap_path, TEST_DIR / "p6_test.proto",
            "-d", "tcp.port==50004,p6test.sample",
            "-o", "p6test.sample.tcp_framing:varint",
        )

        self.assertIn("label: hello-p6", output)
        self.assertIn("label: second-message", output)


if __name__ == "__main__":
    unittest.main()
