#!/usr/bin/env python3
#
# Copyright (c) 2015, 128 Technology, Inc.
# Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
#
# This code is licensed under the MIT license.

"""Compare bundled SSR schemas with an SSR checkout, ignoring comments."""

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ("bfd.proto", "ip.proto")


def normalized_schema(path):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def resolve_proto_dir(value):
    path = Path(value).expanduser().resolve()
    if (path / "bfd.proto").is_file() and (path / "ip.proto").is_file():
        return path
    return path / "src" / "lib" / "protobuf"


def main():
    configured = os.environ.get("SSR_PROTO_DIR")
    default = ROOT.parent / "ssr" / "src" / "lib" / "protobuf"
    source_dir = resolve_proto_dir(configured) if configured else default

    if not source_dir.is_dir():
        print(
            "Skipping SSR schema drift check; set SSR_PROTO_DIR to an SSR "
            "checkout or its src/lib/protobuf directory."
        )
        return 0

    mismatches = []
    for name in SCHEMAS:
        source = source_dir / name
        bundled = ROOT / "files" / name
        if not source.is_file():
            print("SSR schema is missing: {}".format(source), file=sys.stderr)
            mismatches.append(name)
            continue
        if normalized_schema(source) != normalized_schema(bundled):
            print("Schema drift detected: {}".format(name), file=sys.stderr)
            mismatches.append(name)
        else:
            print("Schema matches SSR: {}".format(name))

    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
