# Verified Production Trust Model, Zero-SSH Substantiation & Self-Hosting Guide

This document defines the exact security invariants, **separate host/control-plane trust boundaries**, staged rollout path, and constellation governance rules for Proof of Geography.

---

## 1. Two Strictly Separated Modes (Diagnostics vs. Verified Production)

1. **Diagnostic / Test Network Mode (Active Today — 42 `SoftwareDev` Anchors):**
   - The running 42-node tri-cloud fleet (`web/data/anchors.json`) remains online for map QA, geometry testing, and empirical spatial likelihood calibration.
   - All results from `SoftwareDev` nodes are explicitly labeled **Diagnostic / Unverified — NOT Hardware Proof**. Diagnostics are never blocked on hardware rollout, never shut down prematurely, and never mislabeled as hardware-proven.
2. **Verified Production Mode (Fail-Closed Hardware TEE):**
   - Every production constellation member MUST run its measuring and signing workload inside a vendor-verified hardware TEE (`AmdSevSnp`, `IntelTdx`, or `AwsNitro`), boot from a **published reproducible immutable zero-SSH image**, serve fresh caller-nonce vendor-verifiable attestation bound to its live ephemeral Ed25519 probe key, and carry a separate audited `coordinate_basis`.
   - If too few verified hardware anchors are available, verifiers return **`InsufficientVerifiedAnchors` / no proof** — never silently substituting `SoftwareDev` or external nodes.

---

## 2. Official Constellation Exclusivity & Self-Hosting (`?registry=<url>`)

- **Official Constellation = Operated by Proof of Geography Only:**
  - The official constellation (`web/data/anchors.json`, `/.well-known/pog-network.json`) contains **only** nodes operated by Proof of Geography.
  - Third-party nodes are **not** added to the official registry, there is **no** community admission PR workflow, and external nodes are **never** merged into official proofs or official hardware counts.
- **Self-Hosting an Independent Constellation:**
  - Any independent operator can run their own constellation, generate their own offline Ed25519 root key (`pog-cli network init`), sign their own registry (`pog-cli network sign-registry`), and serve their own HTTPS `/info`, `/attest`, and `/ping` endpoints via optional per-anchor `https_url` (see [examples/external_constellation_registry.json](../examples/external_constellation_registry.json)).
  - Opening `https://proofofgeography.com/?registry=https://pog.example.org/.well-known/pog-network.json` **selects that separate constellation** rather than merging it with the official roster.
  - The UI labels external constellations as **Independently Operated**, counts attested hardware (`Intel TDX`, `AMD SEV-SNP`, `AWS Nitro`) **only within the selected constellation**, and explicitly states that **hardware verification is not official Proof of Geography membership**.

---

## 3. Substantiating Zero-SSH / Zero-Remote-Exec Inside the Measured Image

A closed TCP port 22 firewall rule is **not** proof that an operator or host compromise cannot enter the running workload — firewall rules live in the untrusted cloud control plane and can be toggled at any time without changing the enclave measurement.

Instead, every production member substantiates **no SSH server, no interactive admin shell, and no remote command path** directly inside the **cryptographically measured immutable image**, gated by `scripts/release_gate.py`:

| Platform | Measured Image Recipe | Substantiated Zero-SSH / Zero-Shell Properties | Measured Cryptographic Digest |
| :--- | :--- | :--- | :--- |
| **AWS Nitro Enclaves** | `infra/images/Dockerfile.anchor` + `infra/images/build-nitro-eif.sh` | Final stage is `FROM scratch` containing ONLY static musl `pog-anchor`, CA bundle, and `SHA256SUMS`: **no `sshd`, no `/bin/sh`, no `busybox`, no package manager, no network interface (AF_VSOCK only)**, and zero `--allow-dev-*` flags. | Non-zero SHA-384 `PCR0`, `PCR1`, `PCR2` signed by AWS Nitro NSM under pinned **AWS Nitro Root-G1** (`641a0321...79bb5b`). |
| **GCP / Azure AMD SEV-SNP** | `infra/images/flake.nix` + `infra/reproducible/Dockerfile` (immutable UKI / dm-verity rootfs) | `services.openssh.enable = false`, `users.mutableUsers = false`, `security.sudo.enable = false`, serial/local getty & emergency shells disabled (`rd.shell=0`, `rd.emergency=halt`), zero `google-guest-agent` / OS-Login / metadata SSH-key daemon, zero `--allow-dev-*` flags. | Pinned SEV-SNP Launch Digest + measured boot chain verified against pinned **AMD ARK-Milan / Genoa / Turin** (`69d063b4...`, `4c6598d1...`, `1f084161...`) via RSA-PSS-4096 + VCEK ECDSA P-384. |
| **GCP / Azure Intel TDX** | `infra/images/flake.nix` + `infra/reproducible/Dockerfile` | Same immutable zero-SSH, zero-shell, zero-remote-exec image policy as SEV-SNP. | Pinned `MRTD` + `RTMR0..3` verified against embedded DCAP PCK chain up to pinned **Intel SGX Root CA** (`44a0196b...fb674d3`). |

> **Published Zero-SSH Static OCI Artifact (Publicly Pullable, Pinned by Digest):**
> - **Pinned Reference (`linux/amd64`, `FROM scratch`):** `ghcr.io/jperla/proof-of-geography/pog-anchor@sha256:1cb78384b703fa1edf0825ceb8d94e2e7325c1173c1bfe785678b11ddaffee9f`
> - **Reproducible Static Musl `pog-anchor` Binary SHA-256:** `774fb046526e78c304c648353ae93fd541bc08fa6a4371e0c1fa0e856496f477` (bit-for-bit verified across independent local and GitHub Actions builds; rootfs contains only `/usr/local/bin/pog-anchor`, `/etc/ssl/certs/ca-certificates.crt`, and `/etc/pog/SHA256SUMS` — zero `sshd`, zero `/bin/sh`, zero package manager).
>
> **GCE AMD SEV-SNP Preflight Gate & Firmware-to-Workload Chain Gap:**
> - Official Google Cloud Confidential Space documentation (`deploy-workloads`) lists only `SEV` and `TDX` (not `SEV_SNP`), even though `confidential-space-261100` carries `SEV_SNP_CAPABLE` / `SNP_SVSM_CAPABLE` image flags. We do **not** downgrade `SEV_SNP` VMs to Gen-1 `SEV` and do **not** run unsupported Confidential Space boots on `SEV_SNP`.
> - On GCE AMD SEV-SNP, raw `/dev/sev-guest` `MEASUREMENT` (`0x90..0xC0`) hashes only GCE OVMF firmware — not the disk, kernel, initrd, or container digest. Turning an `SEV_SNP` VM into a verified zero-SSH canary requires either: (a) a reproducible bootable GCE custom image (locked UKI + `dm-verity` immutable rootfs, zero SSH/getty/metadata boot overrides) plus vTPM/SVSM PCR + TCG event-log attestation chained to the fresh SEV-SNP report in `pog-anchor` and `pog-tee`/`verify_public_node.py`; or (b) a separate approval for an officially supported Intel `TDX` Confidential Space canary with `teeserver.sock` OIDC attestation (`submods.container.image_digest` + `eat_nonce`) verification wired into `pog-anchor` and the verifiers.

---

## 4. Simple Public Verification (Zero Credentials, Zero SSH)

Any third party can verify a node with **no cloud credentials and no SSH**:

```bash
# 1. Verify a live hardware TEE node (fresh /attest?nonce= when upgraded, or /info audit today)
python3 scripts/verify_public_node.py \
  --url http://35.207.136.128:7445 \
  --check-ssh-port

# 2. Verify a production node strictly (requires fresh caller nonce + Ed25519 PoP + pinned measurement)
python3 scripts/verify_public_node.py \
  --url https://fra-gcp.a.proofofgeography.com \
  --expected-measurement <PUBLISHED_96_HEX_MEASUREMENT> \
  --require-fresh-attest \
  --check-ssh-port
```

---

## 5. Remaining Host & Control-Plane Trust (Documented Separately)

Hardware TEE remote attestation is powerful, but it is **not magic**. The following trust assumptions remain outside the enclave boundary and MUST be evaluated separately:

1. **Physical Coordinates (`coordinate_basis`):**
   - Hardware TEE attestation proves *what measured code generated the live signing key on genuine AMD/Intel/AWS silicon* — it **NEVER proves where the datacenter physically sits**.
   - Physical coordinates remain grounded in separate audited provenance (cloud region/AZ/facility basis + continuous cross-cloud anchor-to-anchor speed-of-light consistency checks + conservative coordinate uncertainty folded into Vacuum `c₀` outer bounds).
2. **Silicon, Firmware & Vendor Root CA Supply Chain:**
   - Relies on AMD (PSP/SEV-SNP firmware + ARK/ASK/VCEK), Intel (TDX module/QE + SGX Root CA/PCS), or AWS (Nitro hardware/hypervisor + Nitro Root-G1) not issuing forged quotes or suffering unpatched microarchitectural key extraction. Multi-cloud Byzantine quorums (`min_cloud_providers >= 2`, `f >= 1`) mitigate single-vendor compromise.
3. **Host Network Stack, Parent Relay & Latency Inflation (Fail-Safe Direction):**
   - The cloud host, parent EC2 relay (for AWS Nitro), BGP routing, and NIC remain outside the enclave.
   - A malicious or overloaded host/network can **delay or drop** packets (denial of service or inflating RTT), which strictly **widens** the conservative speed-of-light outer region (fail-safe; never causes false geographic exclusion). It **cannot** forge Phase 2 `BLAKE3-MAC` responses (session key stays in enclave RAM) or shorten physical light travel time.
4. **TLS Edge Termination & DNS:**
   - Where `nginx` terminates public HTTPS on the parent host, TLS protects transport privacy only; authenticity of `/attest`, `/info`, and `AnchorReceipt` rests solely on the enclave-generated Ed25519 key and hardware vendor signature, NOT on the web TLS certificate.
5. **Wall-Clock Timestamps vs. Monotonic RTT Timing:**
   - Phase 2 RTT duration uses the enclave's local monotonic clock (`Instant::now()`).
   - Wall-clock Unix timestamps for quote/receipt expiration rely on host/NTP time sync within policy skew bounds, while freshness against replay relies on the **verifier's own unpredictable random nonce** (`caller_nonce_hex` / `epoch_challenge_hex`).
6. **Cloud Control-Plane Lifecycle & Availability:**
   - The cloud operator or account administrator can stop, reboot, or delete VMs/enclaves. Ephemeral RAM-only Ed25519 keys + strict live-key endorsement matching ensure any restart immediately invalidates old endorsements until fresh re-attestation and re-endorsement occur.

---

## 6. Staged Rollout Sequence

1. **Stage 0 (Current):** Keep the 42-node `SoftwareDev` test network running for browser diagnostics, map QA, and calibration (labeled diagnostic, never proof).
2. **Stage 1 (GCP Canary — Zero New Compute Spend):** Re-image 1 of the 8 running unpublished GCP Confidential VMs (`gcp-europe-west3-frankfurt` SEV-SNP or `gcp-us-east4-ashburn` TDX) onto the reproducible zero-SSH measured image, publish its exact expected measurement + `/attest?nonce=` + HTTPS `:443`, verify via `scripts/verify_public_node.py --require-fresh-attest` and `scripts/release_gate.py`, then roll across the remaining 7 unpublished GCP SEV-SNP/TDX VMs.
3. **Stage 2 (AWS Nitro & Azure CVM Canaries — Pending Sizing Approval):** Roll 1 AWS Nitro canary (`c6g.large` AL2023 `arm64` or `c6a.xlarge` `x86_64`) and 1 Azure SEV-SNP canary (`Standard_DC2as_v6` with corrected `eastus` coordinates), pass all 5 zero-dev-fallback acceptance checks, then migrate regional waves.
4. **Stage 3 (Verified Production Registry Cutoff):** Publish Verified Production mode strictly backed by nodes passing Stage 1–2 (`configured == reachable == attested == proof_eligible`), keeping diagnostics isolated.
