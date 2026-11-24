# Wireshark Protobuf Dissector

A Wireshark Lua plugin for decoding Protocol Buffers and SSR Secure Vector Routing (SVR) traffic.

Last reviewed: 2026-11-24.

## GUI quick start

1. Follow Wireshark's [plugin folder instructions](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)
   to locate your personal Lua plugins folder. In Wireshark, you can also find
   **Personal Lua Plugins** under **Help → About Wireshark → Folders**. Create
   the folder if needed.

2. Keep the runtime files together **outside** Wireshark's plugin folders:
   `protobuf.lua`, `settings.lua`, `svr.lua`, `ssr_bfd.lua`, the complete
   `modules/` directory, and `files/bfd.proto` plus `files/ip.proto` under
   `files/`. Tests and captures are not required.

3. Copy only [svr_loader.lua](./svr_loader.lua) into the personal Lua plugins
   folder. Edit the copy to set `protobuf_file` to the absolute path to the
   project's `protobuf.lua`:

   ```lua
   local protobuf_file = "/absolute/path/to/protobuf.lua"
   ```

   On Windows, use forward slashes (for example, `C:/path/to/protobuf.lua`).
   Do not copy the other project Lua files into Wireshark's plugin folders;
   they are loaded independently and cause initialization errors. The optional
   `native/svrcrypto.so` is a Lua module, not a Wireshark binary plugin.

4. Restart Wireshark, open a capture, and filter with `svr || ssr_bfd`. Select
   an SVR packet and expand **Secure Vector Routing** in the packet-details
   pane. Reload later Lua or schema changes with **Analyze → Reload Lua Plugins**.

5. If packets use an HMAC trailer, enable **HMAC trailer present** and set
   **HMAC trailer length** to its configured size in Wireshark's SVR protocol
   preferences. This separates the trailer but does not verify it. Encrypted
   metadata and payload remain opaque without matching keys and the native
   module.

Alternatively, launch the GUI with the script directly (macOS):

```sh
/Applications/Wireshark.app/Contents/MacOS/Wireshark \
  -X "lua_script:/absolute/path/to/protobuf.lua"
```

On Linux or Windows, use the Wireshark executable for that installation with
the same `-X lua_script:<path>` option. Do not use this option and the loader
at the same time.

## Features

- Decode SVR headers and metadata TLVs, with malformed-packet diagnostics.
- Decode SSR BFD/ESKM metadata and correlate metadata-key indices with SVR rekeys.
- Decode protobuf using bundled or user-supplied schemas, including proto2/proto3, maps, packed fields, and framed TCP.
- Decrypt SVR AES-CBC/GCM sections when the native module and matching keys are available; hand known plaintext payloads to Wireshark dissectors.

## Requirements

- Wireshark or `tshark` 3.6 or newer, with Lua support enabled. Regression tests have run with `tshark` 4.4.9 and 4.6.10.
- Python 3 to run the regression suite.
- A C compiler, Lua 5.4 development headers, `pkg-config`, and libgcrypt are needed only for native decryption.

## Native decryption build

The native module is optional and must be built on the machine running
Wireshark. On macOS with Homebrew:

```sh
brew bundle install
make -C native
```

On Linux, install Lua 5.4 development headers, libgcrypt development files,
`pkg-config`, and a C compiler, then run `make -C native`. Without the module,
encrypted sections remain opaque.

## TShark quick start

Load the plugin with `tshark` to recognize SVR packets and decode SSR BFD metadata:

```sh
tshark -X lua_script:/path/to/protobuf.lua \
  -r capture.pcap \
  -Y 'svr || ssr_bfd' \
  -T fields -e frame.number -e _ws.col.Protocol -e _ws.col.Info
```

SVR packets are heuristically recognized using the SVR cookie and header checks. SSR BFD control packets are decoded on UDP port 1280 by default. Plaintext BFD packets carried through an SVR waypoint can be handed to the BFD dissector when SVR payload decoding is enabled.

## Protobuf usage

To decode another protobuf protocol, load its schema and select its outer message with **Decode As** or `tshark -d`:

```sh
tshark -X lua_script:/path/to/protobuf.lua \
  -X lua_script1:/path/to/messages.proto \
  -r capture.pcap \
  -d udp.port==9000,example.packet
```

The protocol name is the lowercase package and message name joined with dots, as in `example.packet`. For multiple schemas, add another `-X lua_script1:/path/to/file.proto` argument.

### TCP message framing

Protobuf has no built-in message boundary for TCP streams. Set the selected message protocol's **TCP framing** preference to match the sender:

| Value | Framing |
|---|---|
| `none` | Treat each TCP PDU as one protobuf message; no reassembly. |
| `length32` | Four-byte big-endian message length, followed by message bytes. |
| `varint` | Protobuf-style varint length, followed by message bytes. |

For example:

```sh
tshark -X lua_script:/path/to/protobuf.lua \
  -X lua_script1:/path/to/messages.proto \
  -r capture.pcap \
  -d tcp.port==9000,example.packet \
  -o example.packet.tcp_framing:length32
```

The selected framing applies to that message protocol. UDP messages are unaffected.

### SSR protobuf schemas

`files/bfd.proto` and `files/ip.proto` provide SSR BFD/ESKM protobuf definitions, including ML-KEM key metadata and AES-GCM cipher enums. They are loaded with the plugin. To load additional schemas from an SSR build, set the **SSR protobuf directory** preference on `Google Protobuf Format (Lua)` or the `SSR_PROTOBUF_DIR` environment variable before launching Wireshark.

Weak imports load when their files exist and fail explicitly when files are
missing. Leading Doxygen-style field comments can set labels and descriptions:

```proto
/// @name Friendly label
/// @desc Human-readable field description
optional string label = 1;
```

## SVR preferences and filters

| Preference | Values / purpose |
|---|---|
| `svr.md_encrypted` | `auto`, `always`, or `never` for payload metadata. `auto` parses plausible TLVs; otherwise it attempts decryption when a key matches. |
| `svr.payload_encrypted` | `auto`, `always`, or `never` for inner payloads. `auto` decrypts only when metadata marks the session encrypted and a key matches. |
| `svr.hmac_enabled` | Mark an HMAC trailer as present so it can be split from the packet. |
| `svr.hmac_length` | Trailer length in bytes: 16, 20, 32, 48, or 64. |
| `svr.cipher` | `aes-cbc` or `aes-gcm`; selects cipher mode for metadata and payload decryption. |
| `svr.keys` | Semicolon-separated decryption keys. See key selectors below. |
| `ssr_bfd.udp_port` | UDP port for SSR BFD control packets; defaults to 1280. |

### Decryption keys

Set `svr.keys` to semicolon-separated `selector=hex-key` entries. Keys must be 16 bytes (AES-128) or 32 bytes (AES-256), encoded as hexadecimal. Selectors identify the SVR key scope:

| Selector | Matches |
|---|---|
| `sid:N` | Security Identifier TLV 16; fallback for metadata and payload |
| `rekey:N` | SVR2 rekey index from TLV 49; preferred for encrypted metadata |
| `payload:N` | SVR2 payload index from TLV 49; preferred for encrypted inner payload |

Optionally scope an entry to either outer endpoint by appending `@IP`. Example:

```sh
tshark -X lua_script:/path/to/protobuf.lua \
  -o svr.cipher:aes-gcm \
  -o 'svr.keys:sid:1234=00112233445566778899aabbccddeeff;rekey:9=ffeeddccbbaa99887766554433221100' \
  -r capture.pcap
```

Wireshark stores preference values locally; key values are not displayed in packet trees or logs. Treat Wireshark preference files as secret-bearing files. Avoid passing real keys with command-line `-o`, which may expose them through shell history or process listings. AES-GCM authentication failures leave bytes encrypted. AES-CBC uses SSR's zero-padding convention and has no authentication; the dissector marks its plaintext as unverified. HMAC trailers are split but are not verified.

Useful display filters include:

```text
svr
ssr_bfd
svr.malformed_tlv
svr.unknown_type
ssr_bfd.saturated_length
svr.eskm_key_index
svr.eskm.rekey_index
```

The Info column reports SVR metadata and ESKM/SVR2 key-index correlation. ESKM
key bytes remain opaque; SVR sections can be decrypted separately with matching
keys.

## Testing

Run the full suite: native crypto, synthetic SVR/BFD, protobuf, schema checks,
and real captures when available.

```sh
TSHARK=/path/to/tshark sh test/run_tests.sh
```

The runner also checks bundled schemas against a local SSR checkout. Set
`SSR_PROTO_DIR` to the checkout or its `src/lib/protobuf` directory when it is
outside the default location.

Generate a deterministic synthetic matrix capture:

```sh
python3 test/svr/gen_svr_pcaps.py --output /tmp/svr_matrix.pcap
```

Real captures remain local and Git-ignored because they contain identifying
data; their tests skip when captures are absent.

## Limitations

- Decryption requires a compatible `native/svrcrypto.so` build and configured key. Without either, encrypted bytes remain opaque.
- The `hmac_enabled` preference only separates trailer bytes; it does not verify HMAC authenticity. AES-CBC plaintext is unauthenticated.
- SVR-over-TCP does not have TCP stream reassembly. TCP framing options apply to protobuf message dissectors.
- Protobuf extensions and `message_set_wire_format` are unsupported. Map keys must use native scalar types.
- The SSR protobuf directory preference compiles files from that directory as a separate schema set; cross-imports into the plugin's bundled `files/` set are not merged.
- No screenshot is included. Real captures may contain sensitive packet data, so use sanitized input for screenshots or examples.

## Contributing

See the [project repository](https://github.com/128technology/protobuf_dissector) for source, issues, and contribution discussion.

## License

Copyright (c) 2015 128 Technology, Inc.

Copyright (c) 2026 Hewlett Packard Enterprise Development LP.

This project is licensed under the MIT License. See [LICENSE.md](./LICENSE.md).
