# Capacity, Throughput & Economics: Running Proof of Geography Like DNS

One of the best properties of this architecture is that **operating a global Proof of Geography network costs roughly the same as a small DNS cluster (~\$1.1k–\$2.2k/mo)** while easily authenticating **trillions to quadrillions of client requests per year**.

---

## 1. Empirical Microbenchmarks (Measured via `pog-cli bench`)

Measured on a single modern CPU core (`cargo run --release --bin pog-cli -- bench --verify-iters 5000`):

| Operation | Measured Latency | Single-Core Throughput | Impact on Physics Radius |
| :--- | :---: | :---: | :--- |
| **Phase 2 Prover `BLAKE3-MAC` (64B packet)** | **72.7 ns** | **13.76M ops/sec** | `< 0.0001 ms` (`< 15 meters`!) |
| **Client Full Offline Verification** *(TEE quote + 6 Ed25519 sigs + $O(K^3)$ Byzantine core)* | **131.5 µs** | **7,606 verifies/sec** | Runs strictly off-path at the client |

---

## 2. How Many Trillions of Requests Can a 24-Node Grid Handle?

There are **two distinct layers of scale**, just like **DNS / TLS Certificate Authorities**:

### Layer A — Raw Live UDP Distance-Bounding Proofs (Anchor Grid Capacity)
* Each Phase 2 UDP round exchanges one **64-byte Challenge** + one **64-byte Response** (128 bytes total on the wire).
* A full 8-round distance-bounding burst transfers **1,024 bytes** (~1 KB) plus ~1.5 KB for Phase 1 TCP/X25519 setup (~2.5 KB total per Anchor per proof).
* A single pinned Linux UDP core with `SO_BUSY_POLL` / standard socket I/O comfortably sustains **120,000 packets/sec** (kernel DPDK/AF_XDP easily exceeds **1,000,000+ pkt/sec** per core).
* At 8 rounds per burst:
  * **Per Anchor node (conservative kernel UDP):** `120,000 / 8 = 15,000 bursts/sec` (15 MB/s bandwidth = ~120 Mbps, trivial on a 10 Gbps cloud NIC).
  * **Across 24 Anchor nodes (`K = 6` Anchors per proof):** `(24 / 6) × 15,000 = 60,000 raw live proofs/sec`.
  * **Annual raw live proofs (conservative):** `60,000 × 31,536,000 s` = **~1.89 TRILLION raw live proofs / year** (~157 billion / month).
  * **With AF_XDP / 4 cores per Anchor:** **~15+ TRILLION raw live proofs / year**.

### Layer B — Handshake-Attached & Hourly-Cached Authenticated Requests (DNS-Style Scaling)
Just as browsers do not call Let's Encrypt on every HTTPS GET request, AI inference clients and enterprise workloads **do not** need the Anchor grid on every single token or HTTP call:

1. **Continuous Hourly Chain:** Every attested GPU node / datacenter server refreshes its signed `GeoProofBundle` once per hour (or every 5 minutes for high-assurance workloads).
2. **Zero-Anchor Client Verification:** The Prover attaches its compact `X-PoG-Proof` bundle inside the TLS/RA-TLS handshake (or HTTP response header). Clients verify it offline in **131.5 µs** against the cached public `AnchorGrid` (like DNSSEC root keys!).

Look at what that means at internet scale:
* Suppose **10,000,000 distinct datacenter & GPU servers worldwide** run continuous hourly PoG chains:
  * Load on the 24-node Anchor grid = `10,000,000 / 3,600 s` = **2,778 proofs/sec** (**4.6% of grid capacity!**).
* If each of those servers handles even 100–1,000 API/inference requests/sec verified via handshake-attached proofs:
  * Total authenticated requests = **30 TRILLION to 300+ TRILLION verified requests/day** (**10+ QUADRILLION requests/year**) with **zero additional Anchor traffic**!

---

## 3. Bandwidth & Multi-Cloud Infrastructure Cost (24-Node Grid)

### Compute Cost Breakdown

| Cloud Provider | Nodes | Instance Type | Approx. On-Demand / Node | Approx. 1-Yr CUD / Savings Plan |
| :--- | :---: | :--- | :---: | :---: |
| **GCP** | 8 | `c3d-standard-4` (SEV-SNP) / `c3-standard-4` (TDX) / `n2d-standard-2` | ~\$95–\$135 / mo | ~\$60–\$85 / mo |
| **AWS** | 8 | `c6a.large` (SEV-SNP, 6 nodes) + `c6i.xlarge` (Nitro, 2 nodes) | ~\$56 (c6a) / \$124 (c6i) | ~\$36 / \$78 / mo |
| **Azure** | 4 | `Standard_DC2as_v5` / `Standard_DC2es_v5` | ~\$85–\$100 / mo | ~\$55–\$65 / mo |
| **OVHcloud** | 2 | `b3-8` Sovereign EU Confidential | ~\$35–\$50 / mo | ~\$30 / mo |
| **ByteDance (BytePlus)** | 1 | `ecs.c3t.large` (TDX) | ~\$65 / mo | ~\$45 / mo |
| **Tencent Cloud** | 1 | `S6.MEDIUM4` (SEV-SNP) | ~\$60 / mo | ~\$40 / mo |
| **Total (24 Nodes)** | **24** | **6 Independent Clouds, 3 TEE Silicon Vendors** | **~\$1,800–\$2,300 / mo** | **~\$1,150–\$1,500 / mo** |

### Network Egress Cost
* At **10 million servers running continuous hourly chains** (`~2.4 × 10^8` proofs/day × `2.5 KB/anchor` × `6 anchors` ≈ `3.6 TB/day` globally = `~150 GB/day` per node):
  * Cloud egress across 24 nodes at ~\$0.05–\$0.08/GB adds ~\$200–\$350/mo (or ~\$0 on OVH / Cloudflare peering / Bandwidth Alliance).
* At early public-utility scale (100,000 servers running hourly chains = `~36 GB/day` globally):
  * **Total egress across the entire planet is < \$5/month.**

### Free Public Utility Operating Model (Like DNS / Let's Encrypt)
* **Free Public Tier:** Open-source Anchors funded by a consortium of AI labs, cloud security sponsors, or research grants (total budget < \$25k/year for the full 24-node global grid!), serving free hourly chains and handshake verification for the whole internet.
* **Enterprise / High-Frequency SLA Tier (Optional Future Monetization):** Dedicated sub-second on-demand probing SLAs, custom metro-colocated Anchors (Equinix IBX cages for sub-50-mile hard vacuum bounds), and compliance audit dashboards.
