# Security Fix Report: Authenticated Phase 1 Handshake v2 (`POG-PHASE1-V2`)

**Date:** 2026-11-28  
**Base Commit Audited:** `1480767`  
**Scope:** Local source fix, adversarial regression suite, and verification only.  
**Live Deployment Status:** **NOT DEPLOYED.** Live Constellation Anchors (`v0.1.9`) and `https://llm.proofofgeography.com` have **not** been upgraded, re-attested, or re-pinned. Do **not** claim live nodes are patched until the coordinated rollout checklist below is executed and verified.

---

## 1. Confirmed Vulnerability

During source inspection of commit `1480767`, an authentication gap was confirmed in the untimed Phase 1 key-agreement setup across **both** the direct TCP Anchor path (`crates/pog-anchor/src/main.rs::handle_prover_session`) and the AWS Nitro Enclave `AF_VSOCK` path (`crates/pog-anchor/src/main.rs::handle_enclave_session_stream`), as well as all Phase 1 clients (`pog-prover`, `pog-cli probe-live`, `pog-llm-demo`):

1. **Unauthenticated Prover X25519 DH Key (Core Attack):**
   - `Phase1InitRequest` carried `prover_quote` (binding the Prover's attested Ed25519 public key `pk_P` and `epoch_challenge` into hardware `report_data`) alongside a separate, **unsigned** `prover_ephemeral_x25519_hex`.
   - The Anchor verified `prover_quote`, then independently performed X25519 ECDH with the unauthenticated `prover_ephemeral_x25519_hex` and derived the Phase 2 `BLAKE3-MAC` key via `derive_session_key(shared, session_id, epoch, prover_pk_hex, anchor_id)`.
   - Including `prover_pk_hex` in the KDF did **not** authenticate ownership of `sk_P` or bind `prover_ephemeral_x25519_hex` to `sk_P`. Any attacker who obtained a fresh valid `prover_quote` from a remote victim TEE (for example from a public `X-PoG-Proof` header during the epoch window) could pair that stolen quote with the attacker's **own** local X25519 secret near an Anchor, derive the identical Phase 2 MAC key, answer all Phase 2 UDP challenges locally, and obtain a valid Anchor-signed `AnchorReceipt` falsely placing the victim's attested TEE next to the Anchor.
2. **Unauthenticated Anchor DH Key & Missing Client Verification:**
   - Phase 1 clients (`pog-prover`, `pog-cli probe-live`, `pog-llm-demo`) did not verify `init_resp.anchor_quote`, did not pin `anchor_quote.public_key_hex` or `anchor_quote.vendor` against the trusted Constellation registry (`AnchorDescriptor`), and had no Anchor signature binding `anchor_ephemeral_x25519_hex`, `session_id`, `return_cookie_hex`, `anchor_udp_port`, or `rounds`.
3. **Missing Key Confirmation, Weak-DH Checks, & Nitro Host Relay Binding:**
   - X25519 ECDH did not reject low-order Curve25519 points or non-contributory all-zero shared secrets (RFC 7748 §6.1).
   - Phase 1 terminated with an unauthenticated plaintext `"READY\n"` line (and `HostToEnclaveMsg::Phase2Start { rounds }` on Nitro vsock) with no proof that either peer derived the same authenticated session secret before timing began.
   - On AWS Nitro, the untrusted parent EC2 host supplied `anchor_id` inside `HostToEnclaveMsg::Phase1Start` without cross-checking against a Prover-signed target identity.

---

## 2. Protocol Fix: Mutually Authenticated Phase 1 v2 (`POG-PHASE1-V2`)

The unsafe v1 handshake and `derive_session_key()` were **removed** (preventing accidental compile-time reuse) and replaced with a mutually authenticated, domain-separated, fail-closed **Protocol v2** (`PHASE1_PROTOCOL_VERSION = 2`) implemented once in `crates/pog-proto/src/wire.rs` and enforced across every server and client path.

### Canonical Fixed-Width / Length-Prefixed Transcript Encoding
All signed transcripts use `TranscriptHasher` (SHA-256) with explicit domain tags, fixed-width little-endian integers (`u8`, `u16`, `u64`), fixed-length raw decoded cryptographic values (32-byte keys/nonces/digests, 64-byte `report_data`, 8-byte return cookie), and `u32`-LE length-prefixed variable-length fields (`write_lp`), eliminating delimiter/boundary collisions and hex case ambiguity.

### Three-Message Handshake Flow

1. **Message 1 — `Phase1InitRequest` (Prover → Anchor, `protocol_version = 2`):**
   - Prover generates a fresh 32-byte `prover_nonce` and ephemeral X25519 keypair in RAM.
   - Prover computes `prover_init_transcript_hash = SHA-256(...)` with domain `POG-PHASE1-PROVER-INIT-V2`, committing to:
     - `protocol_version` (`2`), explicit roles `("prover", "anchor")`,
     - `prover_pk` (32B), `prover_measurement` (lp), `prover_report_data` (64B),
     - `target_anchor_id` (lp), `target_anchor_pk` (32B, pinned from trusted registry),
     - `epoch_challenge` (lp, 16..=64B), `prover_nonce` (32B), `prover_ephemeral_x25519` (32B),
     - `prover_udp_port` (`u16` LE), `rounds` (`u16` LE, `1..=16`).
   - Prover signs `prover_init_transcript_hash` with its attested Ed25519 key `sk_P` (`prover_init_sig_hex`), proving live key possession and binding its ephemeral DH key to its attested identity, role, epoch, and target Anchor.
   - All v2 fields are required serde fields (no `#[serde(default)]`), so legacy unsigned v1 requests fail closed immediately.

2. **Message 2 — `Phase1InitResponse` (Anchor / Nitro Enclave → Prover, `protocol_version = 2`):**
   - Anchor (or isolated Nitro Enclave inside `AF_VSOCK`) enforces `protocol_version == 2`, verifies `target_anchor_id == own_anchor_id` and `target_anchor_pk == own_anchor_pk`, verifies `prover_quote` under `prover_tee_policy` and `epoch_challenge`, and verifies `prover_init_sig_hex` under `verified_prover.public_key_hex`.
   - Anchor validates `prover_ephemeral_x25519` against all 7 small-order Curve25519 points (with bit 255 masked), runs X25519 ECDH, and rejects `!shared.was_contributory()` or all-zero `[0u8; 32]` (RFC 7748 §6.1).
   - Anchor generates fresh 32-byte `anchor_nonce`, fresh `session_id: u64`, and stateless 8-byte `return_cookie`.
   - Anchor attests a fresh per-session `anchor_quote` bound to `compute_anchor_quote_nonce(epoch_challenge, prover_nonce) = SHA-256(lp("POG-PHASE1-ANCHOR-QUOTE-NONCE-V2") || lp(epoch_challenge) || prover_nonce)`.
   - Anchor computes the full transcript hash `H_hs = anchor_resp_transcript_hash` with domain `POG-PHASE1-ANCHOR-RESP-V2`, binding `protocol_version=2`, roles `("anchor", "prover")`, `prover_init_hash`, `session_id`, `anchor_id`, `anchor_pk`, `anchor_measurement`, `anchor_report_data`, `anchor_nonce`, `anchor_ephemeral_x25519`, `return_cookie`, `anchor_udp_port`, and `negotiated_rounds`.
   - Anchor signs `H_hs` with its attested Ed25519 key `sk_A` (`anchor_resp_sig_hex`) and derives three domain-separated keys via `derive_handshake_keys_v2(shared_secret, H_hs)` (which again rejects all-zero `shared_secret`):
     - `master_key = BLAKE3_keyed(shared_secret, "POG-PHASE1-SESSION-KEYS-V2" || H_hs)`
     - `phase2_mac_key = BLAKE3_keyed(master_key, "POG-KEY-PHASE2-MAC-V2" || H_hs)`
     - `anchor_confirm_mac = BLAKE3_keyed(master_key, "POG-PHASE1-ANCHOR-CONFIRM-V2" || H_hs)` (returned in `anchor_confirm_mac_hex`)
     - `prover_confirm_mac = BLAKE3_keyed(master_key, "POG-PHASE1-PROVER-CONFIRM-V2" || H_hs)`

3. **Message 3 — `Phase1Confirm` (Prover → Anchor / Nitro Enclave, replaces unsigned `"READY\n"`):**
   - Prover enforces `protocol_version == 2`, exact `anchor_id`, and valid `negotiated_rounds`.
   - Prover verifies `anchor_quote` against `compute_anchor_quote_nonce(epoch, prover_nonce)` using `anchor_handshake_attestation_policy(anchor.tee_vendor, allow_dev_anchors)` — which **always** enforces `AttestationPolicy::production()` (cryptographic vendor root + pinned GCP CS JWKS) for hardware TEE Anchors even if a local developer Prover passed `--allow-dev-tee`.
   - Prover pins `verified_anchor.vendor == anchor.tee_vendor` and `verified_anchor.public_key_hex == anchor.public_key_hex`, verifies `anchor_resp_sig_hex` under the pinned Anchor key, executes checked X25519 ECDH (rejecting low-order / all-zero DH), verifies `anchor_confirm_mac_hex` in constant time (`ct_eq_32`), and sends `Phase1Confirm { protocol_version: 2, session_id, prover_confirm_mac_hex }`.
   - Both direct TCP (`handle_prover_session_with_io`) and the AWS Nitro Enclave (`handle_enclave_session_stream`, via `HostToEnclaveMsg::Phase2Start { rounds, prover_confirm }`) verify `Phase1Confirm` (`protocol_version == 2`, exact `session_id`, constant-time `prover_confirm_mac_hex`, exact `negotiated_rounds`) **strictly before** accepting UDP `PUNCH` or issuing round 0 of Phase 2. Legacy plaintext `"READY\n"` fails closed immediately.
   - Phase 2 timed UDP rounds (`measure_udp_round`, `enclave_measure_vsock_round`) also upgraded to constant-time 32-byte MAC comparison (`ct_eq_32`), and all clients verify `receipt.verify(&anchor.public_key_hex)` upon receipt.

### Remote-Attestation Key Generation & Proof-of-Possession Audit
- Audited `pog-anchor` direct & Nitro enclave key generation (`SigningKey::generate(&mut OsRng)` inside TEE RAM; `--seed-hex` rejected fail-closed on hardware TEEs), Nitro `GetInfo`/`AttestFresh` (enclave never accepts a public key or key hash from the untrusted host), and `pog-tee::verify_quote` (added explicit security invariant documentation clarifying that a TEE quote binds `public_key_hex` to `report_data` and MUST be paired with explicit live Ed25519 proof-of-possession as enforced in Phase 1 v2 and `/attest?nonce=`).

---

## 3. Exact Files Modified

| File | Summary of Changes |
| :--- | :--- |
| `crates/pog-proto/src/wire.rs` | Replaced v1 Phase 1 structs and `derive_session_key` with `PHASE1_PROTOCOL_VERSION = 2` structs (`Phase1InitRequest`, `Phase1InitResponse`, `Phase1Confirm`), canonical `TranscriptHasher`, RFC 7748 low-order / all-zero X25519 rejection (`validate_x25519_public_key_bytes`, `compute_checked_x25519_shared_secret`), `derive_handshake_keys_v2`, `ct_eq_32`, `anchor_handshake_attestation_policy`, and state-machine APIs (`start_phase1_client`, `accept_phase1_anchor`, `finish_phase1_client`, `verify_phase1_confirm`), plus 4 comprehensive unit/adversarial test suites. |
| `crates/pog-proto/src/vsock.rs` | Updated `HostToEnclaveMsg::Phase2Start` to carry `prover_confirm: Phase1Confirm`; switched Phase 2 MAC verification to constant-time `ct_eq_32`. |
| `crates/pog-proto/src/socket.rs` | Switched Phase 2 UDP MAC verification to constant-time `ct_eq_32`. |
| `crates/pog-proto/src/lib.rs` | Exported Phase 1 v2 APIs and removed unsafe v1 `derive_session_key` export. |
| `crates/pog-tee/src/types.rs` | Documented explicit PoP requirement on `verify_quote`. |
| `crates/pog-anchor/src/main.rs` | Enforced Phase 1 v2 mutual authentication and `Phase1Confirm` verification before Phase 2 across direct TCP (`handle_prover_session` / `handle_prover_session_with_io`), Nitro Enclave (`handle_enclave_session_stream`), and Nitro host relay (`run_nitro_host_relay`); updated Nitro e2e test and added full adversarial tests against both real entrypoints plus a live loopback TCP/UDP `handle_prover_session` test. |
| `crates/pog-prover/src/main.rs` | Propagated Phase 1 v2 client handshake, pinned Anchor quote/key/vendor verification, `Phase1Confirm`, and `receipt.verify()`. |
| `crates/pog-cli/src/main.rs` | Propagated Phase 1 v2 client handshake in `run_probe_live` / `live_probe_anchor`, enforcing production Anchor verification for hardware TEE Anchors even when `--allow-dev-tee` is passed on a laptop. |
| `crates/pog-llm-demo/src/pog.rs` | Propagated Phase 1 v2 client handshake in `try_probe_hardware_committee` / `probe_single_anchor` with strict production Anchor verification and `receipt.verify()`. |
| `crates/pog-log/tests/e2e_integration.rs` | Upgraded full $K=6$ live UDP + Merkle transparency-log integration test to execute complete Phase 1 v2 handshakes for all committee Anchors. |
| `docs/ARCHITECTURE.md` | Updated Section 2 Phase 1 specification to match canonical `POG-PHASE1-V2`. |
| `SECURITY_FIX_REPORT.md` | This report. |

---

## 4. Exact Verification & Test Results

All local tests were executed against the patched working tree:

1. **Workspace Unit & Adversarial Tests (Sandboxed — 63/63 PASS, 0 FAILED):**
   - Command: `cargo test --workspace -- --skip test_full_e2e_live_udp_header_and_transparency_log --skip test_live_local_udp_distance_bounding_roundtrip --skip test_direct_anchor_live_tcp_udp_handle_prover_session_end_to_end`
   - `pog-proto` (`17/17 PASS`): includes `test_phase1_v2_valid_mutual_auth_and_key_confirmation`, `test_phase1_v2_adversarial_key_substitution_stolen_quote_and_tampering`, `test_phase1_v2_wrong_anchor_epoch_session_role_and_vendor_downgrade`, `test_phase1_v2_rejects_legacy_unsigned_v1_and_low_order_all_zero_dh`.
   - `pog-anchor` (`6/6 PASS`): includes updated `test_enclave_vsock_end_to_end_challenge_and_signed_receipt`, `test_nitro_enclave_vsock_adversarial_phase1_rejections` (7 attack vectors against real `handle_enclave_session_stream`), and `test_direct_anchor_entrypoint_valid_and_all_adversarial_rejections` (valid flow + 6 attack vectors including stolen quote + attacker DH, legacy unsigned v1 JSON, all-zero DH, and legacy plaintext `"READY"` against real `handle_prover_session_with_io`, asserting Phase 2 never executes).
   - `pog-geo` (`22/22`), `pog-tee` (`8/8`), `pog-prover` (`4/4`), `pog-log` (`2/2`), `pog-telemetry` (`2/2`), `pog-llm-demo` (`1/1`, 1 ignored live-ACME network test), `pog-cli` (`1/1`).
2. **Loopback TCP/UDP Integration Tests (Localhost Socket Permission Required — 3/3 PASS, 0 FAILED):**
   - Command: `cargo test -p pog-anchor test_direct_anchor_live_tcp_udp_handle_prover_session_end_to_end && cargo test -p pog-log --test e2e_integration && cargo test -p pog-proto test_live_local_udp_distance_bounding_roundtrip`
   - `pog-anchor::tests::test_direct_anchor_live_tcp_udp_handle_prover_session_end_to_end`: **PASS** (real loopback `TcpListener` + `handle_prover_session` + scoped UDP `PUNCH` + 3 timed UDP `BLAKE3-MAC` rounds + verified `AnchorReceipt`).
   - `pog-log/tests/e2e_integration.rs::test_full_e2e_live_udp_header_and_transparency_log`: **PASS** ($K=6$ committee Phase 1 v2 + live UDP + Merkle inclusion/STH).
   - `pog-proto::socket::tests::test_live_local_udp_distance_bounding_roundtrip`: **PASS**.
3. **Strict Linting (`0` warnings):**
   - `cargo clippy --workspace --all-targets -- -D warnings`: **PASS**.
4. **Web, Cross-Language Verifier SDKs & Release Gate:**
   - `node --test web/test_geo.mjs`: **11/11 PASS**.
   - `sdks/typescript` (`node --test ./test.ts`): **4/4 PASS**.
   - `sdks/go` (`go test ./...`): **PASS**.
   - `sdks/python` (`unittest discover -v tests`): **5/5 PASS**.
   - `python3 scripts/release_gate.py --self-test`: **8/8 PASS**.

---

## 5. Compatibility & Coordinated Rollout Requirements

- **Intentional Breaking Wire Change on Live Phase 1 (No Silent Downgrade):**
  - `Phase1InitRequest`, `Phase1InitResponse`, and `Phase1Confirm` strictly enforce `protocol_version == 2` and reject legacy unsigned v1 requests and legacy `"READY\n"` signals.
  - Therefore, **v2 clients cannot probe unpatched v1 Anchors**, and **v2 Anchors will reject unpatched v1 clients**.
  - **Offline bundle compatibility preserved:** `AnchorReceipt`, `GeoProofBundle`, `X-PoG-Proof`, `CoarseJurisdictionLease` (`X-PoG-Lease`), and all TypeScript/Python/Go verifier SDKs remain wire-compatible.
- **Required Coordinated Rollout Before Claiming Live Fleet Protection:**
  1. Build and publish a new release (e.g., `v0.2.0`) of static `musl` `pog-anchor` / `pog-cli` / `pog-prover`, the AWS Nitro Enclave ARM64 `.eif` (which changes measured Nitro `PCR0`/`PCR1`/`PCR2`), and the `pog-llm-demo` Confidential Space OCI container (which changes the pinned `sha256:...` container `image_digest`).
  2. Upgrade all 44 live Constellation Anchors (27 AWS Nitro Enclaves + 10 Azure CVMs + 7 GCP Intel TDX/AMD SEV-SNP), collect fresh `/attest?nonce=` hardware attestations, update `config/public_anchors.json` & `config/hw_tee_anchors.json`, re-issue per-Anchor endorsements, re-sign `config/signed_public_network.json` & `config/signed_hw_tee_network.json` with the local offline operator root key, and sync to `https://proofofgeography.com`.
  3. Redeploy `https://llm.proofofgeography.com` on the new v2 `pog-llm-demo` container image and update pinned container digest / Nitro PCR documentation.
  4. Verify live end-to-end (`pog-cli network audit-live --require-fresh-attest`, `pog-cli probe-live`, `pog-cli demo-client --require-geo-quorum`, and confirm live Anchors reject legacy v1 packets).
- **Guidance for the Paper Draft:**
  - Describe the **mutually authenticated Phase 1 v2 protocol (`POG-PHASE1-V2`)** as implemented and verified in the open-source codebase.
  - Accurately note whether live empirical measurements quoted from the earlier `v0.1.9` pilot predate the Phase 1 v2 rollout (Phase 2 timed UDP packets and RTT physics are identical; Phase 1 occurs strictly off the timed critical path), and **do not claim the currently deployed live nodes run v2 until the rollout above is completed**.
