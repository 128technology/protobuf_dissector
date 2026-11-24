# Local real-capture manifest

These captures were supplied for local validation and are excluded from Git.
A field-presence and length-only privacy review found identifying BFD peer-name
fields and certificate/public-key material in the initial exchange capture.
No plaintext metadata-encryption-key field was observed. Keep both captures
local-only; do not commit or share them.

| File | Coverage |
|---|---|
| `svr2_eskm_7.2.5_wan_data_bfd_rekey.pcap` | SVRv2 data and BFD/ESKM control traffic, including one metadata-key rotation. No decryption keys were supplied. |
| `eskm_initial_key_exchange.pcap` | Initial ESKM certificate and DH-key exchange traffic. Certificate and router-identifying fields may be present. |

The test suite skips each real-capture test when its corresponding file is
absent. Synthetic coverage is generated independently by
`test/svr/gen_svr_pcaps.py`.
