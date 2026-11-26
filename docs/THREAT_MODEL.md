# Threat Model & Hardening Analysis

## Adversary Capabilities

We assume a strong adversary who:
* Has **full physical and root hypervisor access** to the Prover server, host OS, NIC, BGP routers, and local clocks.
* Can deploy arbitrary low-latency **front-end reverse proxies, VPNs, BGP Anycast nodes, or AI inference routers** in any city worldwide.
* Can falsify **WHOIS, reverse DNS, and RFC 8805 geofeeds**.
* Can route traffic over **private dark fiber, cloud backbones, or Starlink LEO vacuum laser links**.
* Can physically relocate hardware via **truck, cargo ship/barge, or aircraft** after initial provisioning.
* May compromise or collude with **up to $f$ Anchors** (or an entire single cloud provider's regional control plane when committee size $K$ spans $\ge 3$ independent clouds).

We assume standard cryptographic primitives (`Ed25519`, `X25519`, `BLAKE3`, `SHA-512`) and the hardware isolation of the Prover's CPU TEE (AMD SEV-SNP / Intel TDX / AWS Nitro) hold.

---

## Complete Attack Matrix

| # | Attack | Mechanism | Defense in `proof-of-geography` |
| :--- | :--- | :--- | :--- |
| **1** | **Inference Router / Proxy Relay Lie** | Front-end API in US/EU terminates TLS/ICMP in 1 ms, forwards prompts to cheap offshore GPUs. | Non-exportable `sk_P` inside Prover TEE signs both workload outputs and Phase 2 UDP `BLAKE3-MAC` challenges. Proxy cannot forge MAC; forced to relay nonces to actual GPU host, adding $2d/c$ RTT penalty. `pog-telemetry` also flags `LastHopProxyJump`. |
| **2** | **Split-TEE ("Decoy Enclave")** | Run a legitimate tiny PoG enclave in Frankfurt while running actual LLM inference elsewhere. | **Unified measurement & keypair binding:** PoG responder and inference server run inside the same measured TEE image and share `pk_P` (RA-TLS cert / signed API receipts). For Confidential GPUs, NVIDIA SPDM report hash is bound into CPU `report_data`. |
| **3** | **Physical Relocation / Mobile DC (Boat, Plane, Truck)** | Attest once in a compliant port/city, then move the hardware rack onto a ship, plane, or illicit site. | **Never attest once.** Continuous hourly hash-chained PoG (`pog-log`) + connection-time `X-PoG-Proof` proofs. Disjoint consecutive feasible regions trigger `PhysicalRelocationDetected` immediately; short TTLs expire proofs within 1 hour. |
| **4** | **Starlink LEO Vacuum Laser / Hollow-Core Fiber Relay** | Use space vacuum lasers ($c_0$) or hollow-core fiber ($\approx 0.99 c_0$) to beat standard silica fiber bounds ($c_{\text{fiber}}$) on long hops. | **Tier 1A (`BoundTier::Vacuum`)** enforces $c_0 = 299{,}792.458\text{ km/s}$ with $\delta_{\text{proc}} = 0$, which is strictly uncheatable even over idealized VLEO Starlink laser relays. |
| **5** | **Prover Host Clock Skew / VM Freeze** | Malicious hypervisor slows the Prover VM's clock to shrink measured RTT. | **Prover never measures RTT.** Only remote multi-cloud Anchors run the stopwatch (`SO_TIMESTAMPNS`). |
| **6** | **Anchor Host Clock Tampering / Compromised Cloud** | One cloud provider freezes or skews its Anchor VMs to forge small RTTs. | **AMD SEV-SNP Secure TSC** locks hardware TSC on GCP C3D Genoa **+** multi-cloud committee across 6 clouds (GCP, AWS, Azure, OVH, ByteDance, Tencent) **+** Byzantine $(K-f)$-core verification. |
| **7** | **Sybil / Cherry-Picked / Colluding Anchors** | Prover selects 4 friendly Anchors or registers fake Anchors claiming fake GPS coordinates. | **Public Anchor Registry + Continuous All-Pairs Calibration Mesh** (`CalibrationMatrix` auto-evicts any Anchor violating vacuum speed-of-light against peers) **+ Deterministic Committee Selection** keyed on `(prover_pk, epoch_challenge)` **+ Byzantine $(K-f)$-core**. |
| **8** | **Precomputation / Replay / Pipelining** | Pre-sign challenge responses and cache them on a regional proxy. | Fresh 256-bit OS CSPRNG nonces per round generated *after* the prior round completes, bound to fresh `epoch_challenge` and `client_nonce`. |
| **9** | **Artificial Latency Injection** | Prover adds artificial delay to Anchor A to shift triangulation coordinates elsewhere. | **Upper-bound disks, never thin rings.** Extra delay only enlarges $r_i$, weakening/failing containment and never excluding the true location or shifting the bound to a false city. |
| **10** | **TEE Live VM Migration** | Pass PoG in Frankfurt, then live-migrate encrypted VM memory to another datacenter. | Hardware policy enforces `MIGRATE_MA = 0` (SEV-SNP) / `MIGRATABLE = 0` (TDX) / non-migratable Nitro Enclaves; `sk_P` lives solely in volatile RAM. |
| **11** | **UDP Reflection / Amplification DDoS** | Spoof a victim IP to flood them with Anchor UDP bursts. | Phase 1 authenticated TCP setup + stateless return-routability cookie; symmetric 64-byte UDP Challenge/Response (`amplification = 1.0`). |

---

## Known Limitations & Residual Risks

1. **Physical Side-Channel / Hardware Extraction against a TEE Vendor:** If an attacker extracts the hardware root key from a physical AMD or Intel CPU die via invasive decapping/voltage glitching, they could spoof a single TEE vendor. Mitigations: (a) mix AMD SEV-SNP, Intel TDX, and AWS Nitro across Anchors; (b) physical key extraction on a Prover is costly and detectable via vendor TCB revocations.
2. **Sub-100-Mile Resolution Without a Local Metro Anchor:** Because $1\text{ ms}$ of RTT equals ~93 miles under vacuum speed of light, tightening below ~150 miles requires either a cross-cloud Anchor in the same metro area (e.g., Ashburn, Tokyo, Frankfurt, Singapore, London) or relying on Tier 1B/Tier 2 calibrated bounds over a 24-hour stationary minimum-RTT chain.
3. **Co-located Hardware + Remote Outsourced Compute (Side-Channel Offloading):** A Prover TEE in Zurich could theoretically receive an encrypted prompt, decrypt it, send it over the internet to an unattested GPU in another country, and sign the returned tokens—*unless* the TEE's measured code itself enforces running inference locally inside the enclave / SPDM-bound Confidential GPU (which reproducible open-source TEE images guarantee!).
