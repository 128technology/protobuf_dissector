#!/bin/sh
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

set -eu

if [ -z "${TSHARK:-}" ]; then
    TSHARK=$(command -v tshark || true)
fi
if [ -z "${TSHARK:-}" ] && [ -x /Applications/Wireshark.app/Contents/MacOS/tshark ]; then
    TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark
fi
if [ -z "${TSHARK:-}" ]; then
    printf '%s\n' "tshark not found; set TSHARK to its executable path" >&2
    exit 1
fi

export TSHARK
make -C native test
python3 test/svr/test_core.py
python3 test/svr/test_real_captures.py
python3 test/svr/test_generator.py
python3 test/p6/test_p6_engine.py -v
python3 test/test_schema_drift.py -v
python3 test/check_ssr_proto_drift.py
