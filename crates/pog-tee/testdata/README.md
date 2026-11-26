# AWS Nitro Enclave Hardware Test Vector

`nitro_live_cose.bin` is a real hardware-signed AWS Nitro Enclaves NSM `COSE_Sign1` CBOR
attestation document captured from a production (non-debug) Nitro Enclave running in `us-east-2`
on 2026-11-26:

* **Bootstrap nonce:** `anchor-bootstrap-29928771`
* **Enclave Ed25519 `public_key`:** `76e7961abbd28016bad246b0fc3aa2e91653bf1e6ab9653da0e55adccbb5618b`
* **Bound `user_data` (`report_data`):** `0ba6031f8f4e47634130c883ecf8dc2714137fca20b765b4692656f3ecde19efbabad47f9645ef955753f8e71ea9917b76c49dfa74669a864d1eba6e27724974`
* **PCR0:** `7a94c28fac83f50e11784d318c7418f0161beb1cf0915ed7941dc6bc852b5e872fcd148ad9582b31492617307bacacd0`
* **Document timestamp:** `1795726273` Unix seconds (signing leaf cert valid for ~3 hours around that timestamp)
