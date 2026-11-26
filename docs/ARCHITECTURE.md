# Proof of Geography — System Architecture & Formal Geometry

## 1. Core Architectural Principle: Split Stopwatch from Identity

A common mistake in TEE-based geolocation designs is letting the **Prover TEE** measure RTTs itself. Even on modern Confidential VMs (AMD SEV-SNP / Intel TDX), an untrusted host hypervisor can pause a vCPU (`VMEXIT`) or skew virtualized clock sources unless hardware Secure TSC is strictly enforced—making a 40 ms cross-border round trip appear to take 4 ms.

Our architecture separates the two cryptographic roles cleanly:

1. **Multi-Cloud Anchor TEEs hold the stopwatch.**
   * Deployed across **24 nodes spanning 6 independent cloud providers** (GCP, AWS, Azure, OVHcloud, ByteDance/BytePlus, Tencent Cloud) and **3 hardware TEE vendors** (AMD SEV-SNP, Intel TDX, AWS Nitro).
   * Anchors timestamp raw 64-byte UDP responses in the Linux kernel (`SO_TIMESTAMPNS` + `SO_BUSY_POLL` on isolated RT-priority cores) *before* userspace parsing or MAC verification.
   * The Prover's host cannot alter remote Anchors' clocks.

2. **The Prover TEE holds the unforgeable workload identity.**
   * At enclave boot, the Prover generates an ephemeral Ed25519 keypair `sk_P` strictly inside encrypted TEE RAM (`MIGRATE_MA = 0` disables live VM migration; `DEBUG = 0`).
   * `pk_P` is bound into the hardware attestation quote (`report_data = SHA-512("pog-tee-bind-v1" || pk_P || epoch_nonce || optional_gpu_spdm_hash)`).
   * The **exact same TEE trust domain** runs both the actual workload (e.g., AI inference server, database, API router) and the microsecond UDP responder daemon.
   * For Confidential GPUs (NVIDIA H100/B200 CC), the local PCIe/NVLink SPDM attestation report hash is bound directly into `report_data`, cryptographically tying the GPU silicon to the CPU TEE that passes distance bounding.

---

## 2. Two-Phase Microsecond Protocol

Every **1 ms** of enclave overhead bloats a vacuum speed-of-light disk by **~150 km (~93 miles)**. We eliminate cryptographic jitter from the timed path via a two-phase design:

### Phase 1 — Untimed Authenticated Setup (TCP/TLS)
1. Prover computes deterministic committee selection around its claimed location `L_claim` using `BLAKE3("pog-committee-v1" || pk_P || epoch_challenge || anchor_id)`:
   * Up to **1 co-located metro Anchor** (`< 150 km`) for tight single-circle precision.
   * **4 orthogonal regional Anchors** (1 per compass quadrant: NE, SE, SW, NW) enforcing multi-cloud ($\ge 2\text{–}3$ distinct providers) and multi-silicon diversity.
2. Prover and each Anchor exchange TEE Remote Attestation Quotes and ephemeral X25519 keys, deriving a 32-byte symmetric session key `K_PA` strictly inside enclave RAM, plus a stateless return-routability cookie (blocking UDP reflection/DDoS).

### Phase 2 — Timed Distance-Bounding Burst (Public Internet UDP)
1. Anchor executes $M = 8$ **strictly sequential** rounds (no pipelining):
   * Generates fresh 256-bit OS CSPRNG nonce $N_m$ *immediately* before sending a fixed 64-byte `ChallengePacket`.
   * Records TX monotonic timestamp $t_0$.
   * Prover TEE computes keyed `BLAKE3-MAC(K_PA, session_id || round || N_m || epoch_challenge)` in **< 0.5 microseconds** and replies with a fixed 64-byte `ResponsePacket` (amplification factor = `1.0`).
   * Anchor captures kernel `SO_TIMESTAMPNS` arrival time $t_1$, verifies the MAC, and computes $\text{RTT}_m = t_1 - t_0$.
2. Anchor takes $\text{RTT}_{\min} = \min_{m=1..8} \text{RTT}_m$ (stripping transient internet queueing jitter while remaining 100% lower-bounded by physics) and signs an Ed25519 `AnchorReceipt`.

---

## 3. Physics Bounds & Starlink LEO Laser ISL Analysis

We always set assumed Prover processing delay $\delta_{\text{proc}} = 0$ so faster attacker hardware can never violate a bound:

$$r_i = \frac{c_{\text{eff}} \cdot \text{RTT}_{\min, i}}{2}$$

We report **all three tiers** on every proof:

| Tier | Constant $c_{\text{eff}}$ | Radius / 1 ms RTT | Properties |
| :--- | :--- | :--- | :--- |
| **Tier 1A: Vacuum (`BoundTier::Vacuum`)** | $299{,}792.458\text{ km/s}$ | 149.9 km (93.1 mi) | **Unconditionally uncheatable** by any physical medium—including hollow-core fiber, microwave relays, and Starlink vacuum laser ISLs. |
| **Tier 1B: Silica Fiber (`BoundTier::Fiber`)** | $204{,}000\text{ km/s}$ | 102.0 km (63.4 mi) | Tighter bound uncheatable on standard terrestrial/subsea fiber (including private cloud backbones). |
| **Tier 2: Calibrated (`BoundTier::Calibrated`)** | Learned live from Anchor mesh (~145,000 km/s) | ~72.5 km (~45 mi) | Fused with IPinfo-style traceroute rDNS & RFC 8805 geofeed signals for tight 68% / 95% confidence radii. |

### Why Starlink Matters
Starlink LEO satellites (~550 km shell) pay an unavoidable vertical slant-range penalty (~7.3 ms overhead directly at 90°, ~11.4 ms at 40° elevation), **but** their optical inter-satellite links (ISLs) propagate through vacuum at $c_0$.
* At short/regional distances (< ~4,800 km vs ideal silica fiber; < ~2,000 km vs 1.4x routed terrestrial fiber), terrestrial fiber is faster than Starlink.
* At transcontinental/transoceanic distances (> ~4,800 km), vacuum laser ISLs can beat ideal silica fiber—meaning a sophisticated nation-state adversary could theoretically beat `Tier 1B (Fiber)` over an intercontinental laser relay, **but can NEVER beat `Tier 1A (Vacuum)`** because $2 \cdot \text{slant} + d > d$ always holds.

---

## 4. Exact $O(K^3)$ Byzantine $(K-f)$-Core Geometry on $\mathbb{S}^2$

Let Anchor $A_i$ have unit vector $\mathbf{u}_i \in \mathbb{S}^2 \subset \mathbb{R}^3$ and angular radius $\theta_i = r_i / R_\oplus$. Each upper-bound disk is a single linear half-space intersected with the unit sphere:

$$D_i = \left\{ \mathbf{x} \in \mathbb{S}^2 \;\middle|\; \mathbf{u}_i \cdot \mathbf{x} \ge \cos\theta_i \right\}$$

If at most $f$ out of $K$ Anchors collude with the Prover (reporting fake 0.1 ms RTTs), at least $K - f$ Anchors are honest and **every** honest disk contains the Prover's true location $\mathbf{x}^*$. Therefore $\mathbf{x}^*$ must lie inside the **Byzantine $(K-f)$-core**:

$$S_{\ge K-f} = \left\{ \mathbf{x} \in \mathbb{S}^2 \;\middle|\; \left|\{ i : \mathbf{u}_i \cdot \mathbf{x} \ge \cos\theta_i \}\right| \ge K - f \right\}$$

In `crates/pog-geo/src/byzantine.rs`, we prove $S_{\ge K-f} \subseteq B(\mathbf{u}_{\text{target}}, \theta_{\text{req}})$ **exactly** in $O(K^3)$ operations by checking:
1. Non-emptiness of $S_{\ge K-f}$ via a witness centroid.
2. Every pairwise circle boundary intersection $\partial D_i \cap \partial D_j$ (at most $K(K-1)$ points, solved in closed form via 3D cross products) contained in $\ge K - f$ disks.
3. The unique antipodal-facing point on every single circle boundary $\partial D_i$ opposite $\mathbf{u}_{\text{target}}$ (at most $K$ points) contained in $\ge K - f$ disks.
4. The exact antipode $-\mathbf{u}_{\text{target}}$ (1 check).

For $K = 6, f = 1$, there are at most **37 candidate points**, executing in **microseconds** in pure Rust with zero external GIS libraries.

---

## 5. Dual Consumption Modes: Handshake-Attached + Continuous Hourly Chain

1. **Handshake-Attached (`X-PoG-Proof` / RA-TLS):**
   * On connection setup (or API request), clients pass a `client_nonce` (or TLS exporter secret).
   * The Prover folds it into `epoch_challenge` (live ~150 ms burst) or serves its fresh (< 60 min) signed hourly bundle inside the compact base64url `X-PoG-Proof` header (~2.5–3.5 KB).
   * Clients verify offline in **< 0.5 ms** using only the signed public Anchor registry (DNS-style!).

2. **Continuous Hourly Hash-Chained Transparency Log (`pog-log`):**
   * Every Prover appends an hourly hash-chained proof (`prev_chain_hash -> record_hash`) to an RFC 6962-style signed Merkle transparency log (like Certificate Transparency).
   * **Tightening Stationary Precision:** Across 24+ hours of orthogonal 4-direction measurements, transient internet congestion washes out, allowing verifiers to fuse the per-anchor minimum RTT envelope and shrink the proven radius significantly.
   * **Defeating Mobile Datacenters (Boats / Planes / Trucks):** If a server attests in Ashburn and is later moved onto a ship or aircraft, the new feasible region becomes geometrically disjoint from the historical intersection ($S(t_1) \cap S(t_2) = \emptyset$), triggering an immediate `PhysicalRelocationDetected` alert with implied travel speed.
