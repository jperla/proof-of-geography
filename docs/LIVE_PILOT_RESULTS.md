# Live Multi-Cloud Pilot Results (Real Hardware Intel TDX + AMD SEV-SNP + AWS)

Measured live over the public internet on **2026-11-26** across **9 strictly isolated cloud nodes** spanning **2 independent clouds (GCP + AWS)**, **3 continents (North America, Europe, Asia)**, and **2 real hardware TEE silicon vendors (Intel TDX + AMD SEV-SNP)**:

* **GCP Isolated Project (`pog-pilot-20261125`, custom VPC `pog-isolated-vpc`, Standard Network Tier):**
  * `gcp-us-west1-oregon` — **Real Intel TDX** (`c3-standard-4`, 8,000-byte DCAP quote via ConfigFS TSM)
  * `gcp-us-east4-ashburn` — **Real Intel TDX** (`c3-standard-4`, 8,000-byte DCAP quote via ConfigFS TSM)
  * `gcp-us-central1-iowa` — **Real AMD SEV-SNP** (`n2d-standard-2` Milan, 1,184-byte `/dev/sev-guest` report, `MIGRATE_MA=0`)
  * `gcp-europe-west3-frankfurt` — **Real AMD SEV-SNP** (`n2d-standard-2` Milan, 1,184-byte `/dev/sev-guest` report, `MIGRATE_MA=0`)
  * `gcp-asia-southeast1-singapore` — **Real AMD SEV-SNP** (`n2d-standard-2` Milan, 1,184-byte `/dev/sev-guest` report, `MIGRATE_MA=0`)
* **AWS Isolated VPCs (`10.199.0.0/16` dedicated VPC/IGW/SG per region):**
  * `aws-us-west-1-sanjose`, `aws-us-east-1-nvirginia`, `aws-eu-central-1-frankfurt`, `aws-ap-northeast-1-tokyo` (`c6a.large`)

Every measurement below used the **real Phase 1 (TCP X25519 + TEE Quote) + Phase 2 (UDP NAT-punch + 8 sequential 64-byte `BLAKE3-MAC` rounds + Ed25519 signed `AnchorReceipt`)** protocol—81/81 cross-node exchanges succeeded with 100% valid cryptographic signatures.

---

## 1. Real Live 9×9 Cross-Cloud UDP RTT Matrix (minimum of 8 rounds, ms)

| Prover \\ Anchor | `aws-nrt` | `aws-fra` | `aws-iad` | `aws-sjc` | `gcp-sin` (SEV-SNP) | `gcp-fra` (SEV-SNP) | `gcp-iow` (SEV-SNP) | `gcp-iad` (TDX) | `gcp-pdx` (TDX) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`aws-nrt` (Tokyo)** | 1.15 | 225.97 | 148.37 | 108.55 | 69.85 | 248.86 | 151.62 | 180.06 | 107.64 |
| **`aws-fra` (Frankfurt)** | 224.94 | 0.83 | 91.06 | 149.95 | 169.68 | **1.69** | 117.03 | 87.99 | 145.95 |
| **`aws-iad` (Ashburn)** | 151.43 | 91.49 | 0.21 | 58.88 | 226.17 | 91.96 | 29.84 | **2.19** | 74.81 |
| **`aws-sjc` (San Jose)** | 107.37 | 153.07 | 58.92 | 0.23 | 185.78 | 144.04 | 44.01 | 59.05 | 29.17 |
| **`gcp-sin` (SEV-SNP)** | 68.34 | 170.00 | 225.82 | 182.69 | 0.23 | 156.61 | 205.21 | 222.43 | 155.28 |
| **`gcp-fra` (SEV-SNP)** | 250.98 | **1.70** | 92.29 | 144.43 | 157.99 | 0.24 | 111.46 | 88.36 | 148.54 |
| **`gcp-iow` (SEV-SNP)** | 150.84 | 109.21 | 31.70 | 44.14 | 205.01 | 111.67 | 0.27 | 24.47 | 39.77 |
| **`gcp-iad` (TDX)** | 178.94 | 90.24 | **1.85** | 58.77 | 219.87 | 87.60 | 25.23 | 0.19 | 62.16 |
| **`gcp-pdx` (TDX)** | 110.90 | 146.47 | 74.31 | 30.00 | 154.28 | 148.54 | 39.40 | 61.52 | 0.27 |

### Observed Global Internet Velocity Distribution (`n = 68` cross-region pairs)
* **Median effective speed:** **`130,271 km/s`** (`1.57×` path stretch vs. silica fiber)
* **80th-percentile calibrated bestline:** **`145,145 km/s`**
* **Fastest observed corridor globally:** **`170,869 km/s`** (strictly below both `204,000 km/s` silica fiber and `299,792 km/s` vacuum—zero physics violations!)

---

## 2. Verified Non-Self Cross-Cloud Geography Bounds (Real Hardware TEEs)

Excluding each node's own self-Anchor so every proof relies **exclusively on independent remote Anchors** (verified offline by both the Rust verifier and the zero-dependency Python & TypeScript SDKs):

| Live Prover (Hardware TEE) | Closest Independent Cross-Cloud Anchor | Live Cross-Cloud RTT | Tier 1A Hard Vacuum (`c_0`, Starlink-safe) | Tier 1B Hard Silica Fiber | Tier 2B Calibrated Bestline |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`gcp-europe-west3-frankfurt` (AMD SEV-SNP)** | `aws-eu-central-1-frankfurt` | **1.70 ms** | **158.5 mi** (255.0 km) | **108.0 mi** (173.7 km) | **55.6 mi** (89.5 km) |
| **`aws-eu-central-1-frankfurt`** | `gcp-europe-west3-frankfurt` (AMD SEV-SNP) | **1.69 ms** | **157.7 mi** (253.8 km) | **107.5 mi** (172.9 km) | **55.2 mi** (88.9 km) |
| **`gcp-us-east4-ashburn` (Intel TDX)** | `aws-us-east-1-nvirginia` | **1.85 ms** | **174.7 mi** (281.1 km) | **119.6 mi** (192.5 km) | **65.3 mi** (105.0 km) |
| **`aws-us-east-1-nvirginia`** | `gcp-us-east4-ashburn` (Intel TDX) | **2.19 ms** | **206.6 mi** (332.5 km) | **141.3 mi** (227.5 km) | **82.5 mi** (132.8 km) |

---

## 3. Real Live Probe From a Residential/Office NAT Client (US West Coast -> All 9 Anchors)

Testing `pog-cli probe-live` directly from a macOS laptop behind NAT verified **9/9 Anchors** via UDP NAT-punching + 8-round `BLAKE3-MAC`, with identical verification results across Rust, Python, and TypeScript SDKs:

| Live Anchor | Hardware TEE | Observed Min RTT | Observed p50 RTT |
| :--- | :--- | :---: | :---: |
| `aws-us-west-1-sanjose` | AWS isolated | **8.38 ms** | 10.00 ms |
| `gcp-us-west1-oregon` | **Intel TDX** | **37.73 ms** | 40.28 ms |
| `gcp-us-central1-iowa` | **AMD SEV-SNP** | **65.19 ms** | 69.97 ms |
| `aws-us-east-1-nvirginia` | AWS isolated | **75.31 ms** | 77.16 ms |
| `gcp-us-east4-ashburn` | **Intel TDX** | **80.89 ms** | 85.10 ms |
| `aws-ap-northeast-1-tokyo` | AWS isolated | **108.49 ms** | 110.49 ms |
| `gcp-europe-west3-frankfurt` | **AMD SEV-SNP** | **162.24 ms** | 164.27 ms |
| `aws-eu-central-1-frankfurt` | AWS isolated | **163.50 ms** | 164.69 ms |
| `gcp-asia-southeast1-singapore` | **AMD SEV-SNP** | **193.00 ms** | 195.79 ms |

* **Client-side offline verification (`f=0`, residential last-mile ISP adds ~6–7 ms to San Jose):** `780.8 mi` Vacuum · `531.3 mi` Fiber · `391.7 mi` Calibrated · `108.7 mi` 68% MLE confidence radius.

---

## 4. Real-World Deployment Findings

1. **Cross-cloud metro peering hits 1.7–2.2 ms live**, proving **55–83 miles calibrated** and **158–207 miles hard vacuum (Starlink-safe!)** with real Intel TDX and AMD SEV-SNP silicon.
2. **Real-world cloud TEE availability varies sharply by provider:**
   * **GCP** provides smooth, self-serve hardware **AMD SEV-SNP (`n2d-standard-2` Milan)** and **Intel TDX (`c3-standard-4`)** across major US/EU/APAC zones.
   * **AWS** requires account/region enablement for EC2 AMD SEV-SNP (`UnsupportedOperation` on default accounts); **AWS Nitro Enclaves (`c6i.xlarge`)** is the universally available AWS TEE path across all regions.
   * **Azure** defaults to `0` vCPU quota for `Standard_DC2as_v5` (SEV-SNP) until a quick quota increase is requested.
3. **Empirical internet calibration works:** Observed median global velocity across 68 real pairs was `130,271 km/s` (80th percentile `145,145 km/s`, max `170,869 km/s`), validating why `Tier 1A (299,792 km/s)`, `Tier 1B (204,000 km/s)`, and `Tier 2B (~145k–162k km/s)` cleanly separate adversarial physics from typical fiber routing.
