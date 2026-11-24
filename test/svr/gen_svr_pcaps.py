#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

"""Generate deterministic, dependency-free SVR/BFD regression captures."""

import argparse
import struct
from pathlib import Path


COOKIE = bytes.fromhex("4c48dbc6ddf6670c")
HEADER_TYPES = {1, 16, 18, 20, 21, 23, 24, 26, 28, 39, 40, 45, 46, 48, 49}
FIXED_LENGTHS = {
    1: 10,
    2: 13,
    3: 37,
    4: 13,
    5: 37,
    6: 16,
    8: 4,
    9: 4,
    11: 0,
    12: 0,
    13: 8,
    16: 4,
    18: 0,
    20: 4,
    21: 16,
    24: 1,
    25: 6,
    26: 10,
    27: 12,
    28: 2,
    30: 1,
    31: 8,
    32: 0,
    34: 1,
    39: 4,
    40: 0,
    42: 4,
    43: 0,
    44: 1,
    45: 4,
    46: 1,
    47: 0,
    48: 5,
    49: 2,
    51: 7,
    52: 19,
}


def varint(value):
    if value < 0:
        raise ValueError("protobuf varints must be non-negative")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def proto_uint(field_number, value):
    return varint(field_number << 3) + varint(value)


def proto_bytes(field_number, value):
    return varint((field_number << 3) | 2) + varint(len(value)) + value


def tlv(tlv_type, value):
    return struct.pack("!HH", tlv_type, len(value)) + value


def svr_packet(header_tlvs=b"", payload_tlvs=b"", inner_payload=b"", version=1,
               cookie=COOKIE, declared_header=None, declared_payload=None):
    header_length = 12 + len(header_tlvs) if declared_header is None else declared_header
    payload_length = len(payload_tlvs) if declared_payload is None else declared_payload
    return (
        cookie
        + struct.pack("!HH", (version << 12) | header_length, payload_length)
        + header_tlvs
        + payload_tlvs
        + inner_payload
    )


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_packet(payload, protocol, source_port, destination_port, sequence=1):
    source = bytes((192, 0, 2, 1))
    destination = bytes((198, 51, 100, 2))
    if protocol == 17:
        transport = struct.pack(
            "!HHHH", source_port, destination_port, 8 + len(payload), 0
        ) + payload
    elif protocol == 6:
        transport_header = struct.pack(
            "!HHIIBBHHH",
            source_port,
            destination_port,
            sequence,
            1,
            5 << 4,
            0x18,
            65535,
            0,
            0,
        )
        transport = transport_header + payload
    else:
        raise ValueError("only UDP and TCP are supported")

    total_length = 20 + len(transport)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    ip_header = ip_header[:10] + struct.pack("!H", internet_checksum(ip_header)) + ip_header[12:]
    return ip_header + transport


def minimal_tlv_value(tlv_type):
    if tlv_type in FIXED_LENGTHS:
        size = FIXED_LENGTHS[tlv_type]
        if tlv_type == 23:
            size = 4
        return bytes(size)
    if tlv_type in {7, 10, 14, 15, 17, 19, 22, 29, 33, 35, 36, 37, 38, 41}:
        return b"synthetic"
    return b""


def all_tlv_sections():
    header = b"".join(tlv(t, minimal_tlv_value(t)) for t in sorted(HEADER_TYPES))
    payload_types = [t for t in range(1, 53) if t not in HEADER_TYPES]
    payload = b"".join(tlv(t, minimal_tlv_value(t)) for t in payload_types)
    return header, payload


def bfd_packet(metadata):
    bfd_length = min(255, 24 + len(metadata))
    return bytes((0x20, 0, 0, bfd_length)) + bytes(20) + metadata


def bfd_metadata(field_number, message):
    return proto_bytes(field_number, message)


def node_info(certificate=b""):
    value = proto_uint(1, 7) + proto_uint(2, 123456)
    if certificate:
        value += proto_bytes(4, certificate)
    return value


def address(value):
    return proto_uint(1, value)


def tuple_message(source_port, destination_port):
    return (
        proto_uint(1, source_port)
        + proto_uint(2, destination_port)
        + proto_bytes(3, address(0xC0000201))
        + proto_bytes(4, address(0xC6336402))
    )


def session_data(peername=b"synthetic-peer"):
    value = (
        proto_bytes(1, tuple_message(16400, 16403))
        + proto_bytes(2, tuple_message(16403, 16400))
        + proto_bytes(3, peername)
        + proto_bytes(4, b"synthetic-host")
    )
    return bfd_metadata(1, value)


def key_exchange_metadata(key_type, ack=False):
    key_data = proto_uint(1, key_type) + proto_uint(5, 209)
    if key_type == 0:
        key_data += proto_bytes(2, node_info(b"synthetic-certificate"))
    elif key_type == 1:
        dh_key = proto_bytes(1, b"\xAA" * 32) + proto_bytes(2, b"\xBB" * 16)
        key_data += proto_bytes(3, dh_key)
    elif key_type in (2, 3):
        key_data += proto_bytes(4, b"opaque-synthetic-key")
    elif key_type == 4:
        encap = proto_bytes(1, b"\xCC" * 32) + proto_bytes(2, b"\xDD" * 16)
        ciphertext = proto_bytes(1, b"\xEE" * 32) + proto_bytes(2, b"\xFF" * 16)
        mlkem = proto_bytes(1, encap) + proto_bytes(2, ciphertext)
        key_data += proto_bytes(7, mlkem)
    if ack:
        key_data += proto_uint(6, 1)
    return bfd_metadata(4, key_data)


def echo_metadata(response=False):
    if response:
        echo = proto_bytes(2, proto_uint(1, 17) + proto_uint(2, 18))
    else:
        echo = proto_bytes(1, proto_uint(1, 17))
    echo += proto_uint(3, 1) + proto_uint(4, 1)
    return bfd_metadata(2, echo)


def build_capture_packets():
    header_tlvs, payload_tlvs = all_tlv_sections()
    packets = []

    def udp(payload, source_port=41000, destination_port=41001):
        packets.append(ipv4_packet(payload, 17, source_port, destination_port))

    udp(svr_packet(header_tlvs, payload_tlvs), 41000, 41001)
    udp(svr_packet(tlv(16, struct.pack("!I", 7)) + tlv(49, b"\xD1\x01"),
                   inner_payload=b"opaque-synthetic-data"), 41002, 41003)

    for digest_length in (16, 20, 32, 48, 64):
        hmac_metadata = tlv(16, struct.pack("!I", 7))
        udp(svr_packet(hmac_metadata, inner_payload=b"payload" + b"H" * digest_length),
            41100 + digest_length, 41200 + digest_length)

    session_key_udp = tlv(
        2,
        struct.pack("!4s4sHHB", bytes((192, 0, 2, 10)), bytes((198, 51, 100, 53)),
                    12345, 53, 17),
    )
    dns_query = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    udp(svr_packet(payload_tlvs=session_key_udp, inner_payload=dns_query), 41300, 41301)

    session_key_tcp = tlv(
        2,
        struct.pack("!4s4sHHB", bytes((192, 0, 2, 10)), bytes((198, 51, 100, 53)),
                    12345, 53, 6),
    )
    udp(svr_packet(payload_tlvs=session_key_tcp,
                   inner_payload=struct.pack("!H", len(dns_query)) + dns_query),
        41302, 41303)
    packets.append(ipv4_packet(svr_packet(tlv(16, struct.pack("!I", 8))),
                               6, 41400, 41401))

    udp(svr_packet(header_tlvs=tlv(24, b"\x01")), 41500, 41501)
    udp(svr_packet(header_tlvs=tlv(26, bytes(10))), 41502, 41503)
    udp(svr_packet(header_tlvs=tlv(46, b"\x01")), 41504, 41505)
    udp(svr_packet(header_tlvs=tlv(45, struct.pack("!HH", 1280, 1280)),
                   inner_payload=bfd_packet(key_exchange_metadata(3))),
        41506, 41507)

    udp(bfd_packet(echo_metadata()), 1280, 1280)
    udp(bfd_packet(echo_metadata(response=True)), 1280, 1280)
    for key_type in range(5):
        udp(bfd_packet(key_exchange_metadata(key_type)), 1280, 1280)
    udp(bfd_packet(key_exchange_metadata(3, ack=True)), 1280, 1280)
    ack_only = proto_uint(5, 209) + proto_uint(6, 1)
    udp(bfd_packet(bfd_metadata(4, ack_only)), 1280, 1280)
    udp(bfd_packet(session_data(b"synthetic-" + b"x" * 256)), 1280, 1280)

    malformed_packets = [
        svr_packet(cookie=b"\x00" + COOKIE[1:]),
        svr_packet(version=2),
        svr_packet(declared_header=11),
        svr_packet(declared_payload=8),
        svr_packet(
            header_tlvs=struct.pack("!HH", 16, 5) + b"\x00",
            declared_header=16,
        ),
        svr_packet(header_tlvs=tlv(999, b"")),
        svr_packet(header_tlvs=tlv(16, b"\x00")),
    ]
    for index, malformed in enumerate(malformed_packets):
        udp(malformed, 41600 + index, 41700 + index)

    return packets


def write_pcap(output_path, packets):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, packet in enumerate(packets, 1):
            capture.write(struct.pack("<IIII", index, 0, len(packet), len(packet)))
            capture.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "synthetic" / "svr_matrix.pcap",
        help="output pcap path (default: test/svr/synthetic/svr_matrix.pcap)",
    )
    args = parser.parse_args()
    packets = build_capture_packets()
    write_pcap(args.output, packets)
    print("Wrote {} deterministic packets to {}".format(len(packets), args.output))


if __name__ == "__main__":
    main()
