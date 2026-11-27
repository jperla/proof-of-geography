# Fleet-Wide Hardware TEE Inventory & Phased Migration Plan

> **Product Invariant:** EVERY production Proof of Geography constellation node across **all clouds** (AWS Nitro Enclaves, Azure Confidential VMs, GCP Confidential VMs, and any future provider) MUST run the actual measuring and signing workload inside an independently verified hardware TEE. A single-cloud canary is the first rollout step, **not** the deliverable.
>
> **Coordinate Provenance Invariant:** Hardware TEE identity proves *what code runs inside what vendor-attested enclave* — it does **NOT** prove physical coordinates. Every production anchor MUST maintain a separate, audited `coordinate_basis` (provider region/AZ/facility + cross-cloud speed-of-light audit) and never claim `hardware_identity_proves_coordinates = true`.

---

## 1. Live Fleet Status Summary (Audited Separately — Published vs. Unpublished)

Audit source files (read-only live probes against `https://proofofgeography.com/.well-known/pog-network.json`, AWS EC2 API, Azure Compute/SKU API, and GCP Compute API):
- `proof-of-geography-qa/results/anchor_identity_audit.json`
- `proof-of-geography-qa/results/aws_nitro_state_audit.json`
- `proof-of-geography-qa/results/azure_gcp_tee_state_audit.json`

### A. Published Constellation (`/.well-known/pog-network.json` — 42 Nodes)

| Cloud | Configured (Published) | Reachable (HTTPS & `:7445`) | Live Key Matches Published | Hardware TEE Attested | **Proof-Eligible (Production)** |
|---|---:|---:|---:|---:|---:|
| **AWS** | 14 | 14 / 14 | 0 / 14 | **0 / 14** (`14 SoftwareDev`) | **0 / 14** |
| **Azure** | 14 | 14 / 14 | 0 / 14 | **0 / 14** (`14 SoftwareDev`) | **0 / 14** |
| **GCP (Published)** | 14 | 14 / 14 | 0 / 14 | **0 / 14** (`14 SoftwareDev`) | **0 / 14** |
| **TOTAL PUBLISHED** | **42** | **42 / 42** | **0 / 42** | **0 / 42** | **0 / 42** |

### B. Unpublished GCP Nodes (Strictly Separate — NOT in Published Registry)

| Cloud | Configured (GCP API) | Running | Hardware TEE Configured | HTTPS `:443` / DNS / Registry | **Proof-Eligible (Production)** |
|---|---:|---:|---:|---:|---:|
| **GCP (Unpublished)** | 8 | 8 / 8 | **8 / 8** (`5 SEV_SNP` + `3 TDX`) | 0 / 8 (only `:7445` live; not enrolled) | **0 / 8** (not enrolled / not endorsed) |

> **Unrelated AWS instances observed across all 18 enabled AWS regions (DO NOT TOUCH):** 4 × `m5.xlarge` (`quill-enclave` ASG, `enclave_options.enabled=true`: 2 in `eu-west-1` + 2 in `eu-west-3`) and 1 × `t3.medium` (`tr-eu-clickhouse-1` in `eu-west-3`, `Project=tr-eu-analytics`), plus GCP `pog-web-visualizer` (`e2-small`, `35.212.202.4`). Active AWS Capacity Reservations: `0`, Active Reserved Instances: `0`, Active Savings Plans: `0`. **Confirmed 0 authorized Nitro-Enclave-capable spare capacity available in AWS** (`proof-of-geography-qa/results/aws_spare_and_sizing_audit.json`). Excluded from all Proof of Geography anchor counts and operations.

---

## 2. Root-Cause Analysis: Why 0 / 42 Published Nodes Run Hardware TEEs

1. **AWS (14/14 `SoftwareDev`) — 4 Distinct Missing Layers:**
   - **Layer 1 (Nitro-based EC2 vs. Nitro Enclaves):** All 14 AWS pilot nodes run on `c6a.large` (12) or `c6i.large` (2). While those are Nitro-hypervisor EC2 families, AWS EC2 `describe-instance-types` confirms both `.large` (2 vCPU / 1 physical core) report `NitroEnclavesSupport = "unsupported"` — Nitro Enclaves require >= 4 vCPUs / 2 physical cores (e.g., `c6i.xlarge` or `c6a.xlarge`) so at least 2 vCPUs can be carved off for the enclave while 2 remain for the parent.
   - **Layer 2 (`EnclaveOptions.Enabled`):** `infra/terraform/pilot/aws_isolated_region/main.tf` omitted `enclave_options { enabled = true }`; live EC2 reports `EnclaveOptions.Enabled = false` on 14/14 pilot instances.
   - **Layer 3 (No EIF / No Enclave Runtime / Dev Fallback):** Cloud-init never installed `aws-nitro-enclaves-cli`, never built/loaded a measured `.eif`, and launched `pog-anchor` directly on the untrusted host OS with `--allow-dev-tee --allow-dev-prover` (`aws_isolated_region/main.tf:168`).
   - **Layer 4 (Prior Mock Verifier):** Prior `crates/pog-tee/src/aws_nitro.rs` constructed unsigned local JSON and checked JSON fields instead of calling `/dev/nsm` (`aws-nitro-enclaves-nsm-api`) and cryptographically verifying a COSE_Sign1 ES384 document + X.509 cert chain up to the pinned AWS Nitro Enclaves Root-G1 CA. *(Fixed locally in `crates/pog-tee`, `crates/pog-proto/src/vsock.rs`, `crates/pog-anchor`, and `infra/images/build-nitro-eif.sh` — NOT yet deployed live.)*
2. **Azure (14/14 `SoftwareDev`):**
   - `infra/terraform/pilot/azure_isolated.tf` provisions standard `TrustedLaunch` VMs (`Standard_D2als_v7`, `D2ls_v6`, `D2s_v4`, `D2als_v6`) rather than `ConfidentialVM` (`DCasv5`/`DCasv6` AMD SEV-SNP or `DCesv6` Intel TDX) and launches `pog-anchor` with `--allow-dev-tee --allow-dev-prover` (`azure_isolated.tf:267`).
3. **GCP Published (14/14 `SoftwareDev`):**
   - `infra/terraform/pilot/main.tf` provisions 13 published GCP VMs with legacy **Gen-1 AMD `SEV`** (`n2d-standard-2`, which has no `/dev/sev-guest` attestation device for SEV-SNP) and 1 VM (`gcp-northamerica-south1-queretaro`) on `e2-standard-2` with `confidential_instance_type = None`, launching with `--allow-dev-tee --allow-dev-prover` (`main.tf:333`).
   - Meanwhile, the 8 **unpublished** GCP VMs (`5 SEV_SNP` + `3 TDX`) already have real hardware TEEs on GCP, proving GCP SEV-SNP/TDX works in this project — they simply were not wired into HTTPS `:443`, DNS, and the published registry.
4. **Live Signing-Key Mismatch (0/42 Match `pog-network.json`):**
   - `pog-anchor` generates an ephemeral Ed25519 key in RAM on every startup. The fleet rollout restarted `pog-anchor` after `pog-network.json` and `/etc/pog/endorsement.json` were signed, so every node now serves a fresh ephemeral key paired with a stale endorsement referencing the pre-restart key. *(Fixed locally via strict endorsement-vs-live-key validation on startup/refresh and rejection of stale endorsements in Rust + all SDKs.)*

---

## 3. Complete Per-Node Inventory & Target Hardware TEE Sizing

### 3.1 AWS Published Nodes (14 / 14)

All 14 AWS regions were audited live via `aws ec2 describe-instance-types` (`proof-of-geography-qa/results/aws_spare_and_sizing_audit.json`) and exact Linux On-Demand BoxUsage pricing via AWS Pricing API (`proof-of-geography-qa/results/aws_exact_pricing.json`).
- **Launch-time immutability:** `EnclaveOptions.Enabled` is launch-time only in EC2 (cannot be toggled on an existing running or stopped instance via `modify-instance-attribute`), AND both `c6a.large` (12) and `c6i.large` (2) are explicitly excluded by AWS Nitro Enclaves (`NitroEnclavesSupport = "unsupported"`, 2 vCPU / 1 core SMT). Blue-green instance replacement is required.
- **ARM64 Graviton (Lowest Cost — 14/14 Uniform, Actually Cheaper Than Current Fleet!):** `c6g.large` and `c7g.large` (2 vCPU = 2 dedicated physical cores, no SMT, 4 GiB RAM) report `NitroEnclavesSupport = "supported"` in **14/14 pilot regions** (enclave gets `1 vCPU + 1024–1536 MiB`, parent keeps `1 vCPU + 2.5–3 GiB`). Requires `arm64` static binary + `arm64` `.eif` and `arm64` parent AMI (AL2023 recommended for native signed `aws-nitro-enclaves-cli` RPM).
- **x86_64 (Zero-Arch-Change):** `c6i.xlarge` and `c5a.xlarge` (4 vCPU / 2 physical cores, 8 GiB) are `supported` in **14/14 regions**; `c6a.xlarge` is `supported` in **12/14 regions** (not in `eu-north-1`, `eu-south-1`). `c8a.large` (x86_64 2 vCPU / 2 cores) is `supported` in only `6/14` regions.

| # | Anchor ID | Region | Live IP | Current SKU | `EnclaveOptions` | Target SKU (Recommended) | Alt SKU | Region Enclave Support | Current State (`cfg/rch/att/elig`) |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | `aws-us-east-1-nvirginia` | `us-east-1` | `32.198.57.152` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` (**Canary**) |
| 2 | `aws-us-east-2-ohio` | `us-east-2` | `18.188.171.88` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 3 | `aws-us-west-1-sanjose` | `us-west-1` | `3.101.151.35` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 4 | `aws-us-west-2-oregon` | `us-west-2` | `34.221.78.28` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 5 | `aws-ca-central-1-montreal` | `ca-central-1` | `3.99.220.110` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 6 | `aws-eu-central-1-frankfurt` | `eu-central-1` | `63.184.126.163` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 7 | `aws-eu-west-1-dublin` | `eu-west-1` | `52.212.232.110` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 8 | `aws-eu-west-2-london` | `eu-west-2` | `18.170.43.198` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 9 | `aws-eu-north-1-stockholm` | `eu-north-1` | `13.61.151.44` | `c6i.large` | `false` | `c6i.xlarge` | `c5.xlarge` | Verified `supported` (`c6i`/`c5`) | `1 / 1 / 0 / 0` |
| 10 | `aws-eu-south-1-milan` | `eu-south-1` | `16.22.90.141` | `c6i.large` | `false` | `c6i.xlarge` | `c5.xlarge` | Verified `supported` (`c6i`/`c5`) | `1 / 1 / 0 / 0` |
| 11 | `aws-ap-northeast-1-tokyo` | `ap-northeast-1` | `13.192.214.124` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 12 | `aws-ap-south-1-mumbai` | `ap-south-1` | `13.206.243.206` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 13 | `aws-ap-southeast-2-sydney` | `ap-southeast-2` | `3.107.210.72` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |
| 14 | `aws-sa-east-1-saopaulo` | `sa-east-1` | `54.233.13.128` | `c6a.large` | `false` | `c6a.xlarge` | `c6i.xlarge` | Verified `supported` | `1 / 1 / 0 / 0` |

> **Architecture inside each AWS node:** Untrusted Rocky Linux 9 parent EC2 runs `nginx` (TLS) + `pog-anchor --nitro-host-relay --enclave-cid 16 --vsock-port 7443`. Measured read-only Nitro Enclave `.eif` (`--cpu-count 2 --memory 1024`) runs `pog-anchor --vsock-port 7443`, generates its non-exportable Ed25519 key inside the enclave, obtains hardware NSM COSE_Sign1 attestation from `/dev/nsm` binding `(pk, nonce, PCR0/1/2)`, performs UDP challenge/MAC verification inside the enclave over `AF_VSOCK`, and signs receipts inside the enclave.

### 3.2 Azure Published Nodes (14 / 14)

All 14 Azure regions were audited live via server-side filtered `Microsoft.Compute/skus`. **13/14 regions have unrestricted AMD SEV-SNP (`Standard_DC2as_v6` / `v5`)**; `westus3` also supports Intel TDX (`Standard_DC2es_v6`). **`canadacentral` has 0 unrestricted DC/EC CVM SKUs in this subscription (`NotAvailableForSubscription`)** — requires either an Azure CVM quota/access request for `canadacentral` or migrating that slot to a CVM-enabled region (or excluding it from production membership until CVM-capable).

| # | Anchor ID | Region | Live IP | Current SKU (`SecurityType`) | Target Hardware TEE SKU | Availability / Blocker | Coordinate Audit Note |
|---:|---|---|---|---|---|---|---|
| 1 | `azure-eastus-virginia` | `eastus` | `20.121.204.205` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted (**Canary**) | **BUG FOUND:** `azure_isolated.tf:41-43` lists Boydton VA (`36.6676, -78.3875` = `eastus2`) instead of `eastus` (Ashburn/N. Virginia) -> caused `1.011× c0` violation! **Must fix coordinates before enrolling.** |
| 2 | `azure-westus3-phoenix` | `westus3` | `20.168.77.174` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2es_v6` (Intel TDX) or `DC2as_v6` (SNP) | Unrestricted (TDX + SNP!) | Audited OK |
| 3 | `azure-northcentralus-chicago` | `northcentralus` | `20.25.254.85` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 4 | `azure-southcentralus-sanantonio` | `southcentralus` | `20.225.64.213` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 5 | `azure-canadacentral-toronto` | `canadacentral` | `20.43.23.224` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | **BLOCKED: `NotAvailableForSubscription`** (0 unrestricted CVM SKUs) | Must request Azure CVM SKU unlock for `canadacentral` or keep out of production registry! |
| 6 | `azure-swedencentral-gavle` | `swedencentral` | `20.240.163.134` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 7 | `azure-polandcentral-warsaw` | `polandcentral` | `74.248.19.23` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 8 | `azure-italynorth-milan` | `italynorth` | `172.213.16.253` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 9 | `azure-spaincentral-madrid` | `spaincentral` | `158.158.117.218` | `Standard_D2s_v4` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 10 | `azure-uaenorth-dubai` | `uaenorth` | `20.74.236.111` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 11 | `azure-israelcentral-telaviv` | `israelcentral` | `20.217.188.13` | `Standard_D2ls_v6` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 12 | `azure-southafricanorth-johannesburg` | `southafricanorth` | `40.123.244.36` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 13 | `azure-koreacentral-seoul` | `koreacentral` | `20.196.205.171` | `Standard_D2als_v7` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |
| 14 | `azure-chilecentral-santiago` | `chilecentral` | `68.211.147.7` | `Standard_D2als_v6` (`TrustedLaunch`) | `Standard_DC2as_v6` (SEV-SNP) | Unrestricted | Audited OK |

> **Azure OS Image Requirement:** Azure Confidential VMs (AMD SEV-SNP / Intel TDX) require a CVM-capable OS image with vTPM + `/dev/sev-guest` or `/dev/tdx_guest` kernel support (Ubuntu 24.04 LTS CVM or RHEL/Rocky 9.5+ CVM gallery image) and `security_type = "ConfidentialVM"` with `security_encryption_type = "VMGuestStateOnly"` (or `"DiskWithVMGuestState"`). Existing `TrustedLaunch` VMs must be recreated (blue-green replacement), not in-place resized.

### 3.3 GCP Published Nodes (14 / 14)

| # | Anchor ID | Zone | Live IP | Current SKU & TEE | Target SKU & TEE | Migration Action |
|---:|---|---|---|---|---|---|
| 1 | `gcp-us-east1-sc` | `us-east1-b` | `35.211.23.253` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) or `c3-standard-4` (`TDX`) | Recreate with `confidential_instance_type = "SEV_SNP"` (Verify zone availability) |
| 2 | `gcp-us-south1-dallas` | `us-south1-a` | `34.0.136.121` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) or `c3d-standard-4` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 3 | `gcp-us-west2-losangeles` | `us-west2-b` | `34.4.31.61` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 4 | `gcp-us-west3-saltlakecity` | `us-west3-a` | `35.217.79.137` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Verify `SEV_SNP` zone support in `us-west3`; if unavailable, fail closed (do NOT enroll Gen-1 `SEV`) |
| 5 | `gcp-us-west4-lasvegas` | `us-west4-a` | `35.219.164.8` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Verify `SEV_SNP` / `c3d` zone support; recreate |
| 6 | `gcp-northamerica-northeast1-montreal` | `northamerica-northeast1-a` | `35.215.29.34` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) or `c3-standard-4` (`TDX`) | Recreate with `SEV_SNP` / `TDX` |
| 7 | `gcp-northamerica-south1-queretaro` | `northamerica-south1-a` | `34.2.7.228` | `e2-standard-2` (**`NONE`**) | `c3d-standard-4` (`SEV_SNP`) or `c3-standard-4` (`TDX`) | Check regional Confidential VM availability in `northamerica-south1`; if none, keep excluded from production |
| 8 | `gcp-europe-central2-warsaw` | `europe-central2-b` | `34.0.246.202` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 9 | `gcp-europe-north1-finland` | `europe-north1-b` | `35.217.54.139` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 10 | `gcp-europe-southwest1-madrid` | `europe-southwest1-b` | `34.0.194.213` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 11 | `gcp-europe-west6-zurich` | `europe-west6-b` | `35.216.134.44` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |
| 12 | `gcp-me-central1-doha` | `me-central1-a` | `34.1.45.244` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) / `c3d` | Check `SEV_SNP` zone support; if unsupported, exclude until available |
| 13 | `gcp-me-west1-telaviv` | `me-west1-a` | `34.0.72.189` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) / `c3d` | Check `SEV_SNP` zone support; if unsupported, exclude until available |
| 14 | `gcp-asia-east1-taiwan` | `asia-east1-a` | `35.206.211.6` | `n2d-standard-2` (`SEV` Gen-1) | `n2d-standard-2` (`SEV_SNP`) | Recreate with `SEV_SNP` |

### 3.4 Unpublished GCP Hardware TEE Nodes (8 / 8 — Strictly Separate Inventory)

These 8 GCP VMs are **ALREADY** configured with hardware `SEV_SNP` or `TDX` in GCP and represent the fastest path to our **GCP Canary** without provisioning any new VMs! They only need hardened binary upgrade (`--allow-dev-tee` removed), HTTPS `:443` + DNS (`*.a.proofofgeography.com`), verified vendor-chain quote check, audited `coordinate_basis`, and signed enrollment.

| # | Instance Name | Zone | Live IP | Machine Type | Hardware TEE | Status |
|---:|---|---|---|---|---|---|
| 1 | `gcp-us-east4-ashburn` | `us-east4-a` | `34.4.37.46` | `c3-standard-4` | **Intel TDX** | Running (`:7445` only) — **GCP TDX Canary** |
| 2 | `gcp-us-west1-oregon` | `us-west1-a` | `34.3.99.152` | `c3-standard-4` | **Intel TDX** | Running (`:7445` only) |
| 3 | `gcp-europe-west9-paris` | `europe-west9-b` | `34.1.13.45` | `c3-standard-4` | **Intel TDX** | Running (`:7445` only) |
| 4 | `gcp-us-central1-iowa` | `us-central1-a` | `35.209.22.219` | `n2d-standard-2` | **AMD SEV-SNP** | Running (`:7445` only) |
| 5 | `gcp-europe-west2-london` | `europe-west2-c` | `35.214.10.90` | `n2d-standard-2` | **AMD SEV-SNP** | Running (`:7445` only) |
| 6 | `gcp-europe-west3-frankfurt` | `europe-west3-a` | `35.207.136.128` | `n2d-standard-2` | **AMD SEV-SNP** | Running (`:7445` only) — **GCP SEV-SNP Canary** |
| 7 | `gcp-europe-west4-netherlands` | `europe-west4-a` | `35.214.132.111` | `n2d-standard-2` | **AMD SEV-SNP** | Running (`:7445` only) |
| 8 | `gcp-asia-southeast1-singapore` | `asia-southeast1-a` | `34.2.145.119` | `n2d-standard-2` | **AMD SEV-SNP** | Running (`:7445` only) |

---

## 4. Sizing & Estimated Monthly Cost Impact (Approval Required Before Provisioning)

> **No paid resizing, provisioning, or destructive instance replacement has been performed.** AWS prices below are **exact live AWS Price List API Linux On-Demand (`BoxUsage`, 730 hrs/mo)** summed across all 14 exact pilot regions (`proof-of-geography-qa/results/aws_exact_pricing.json`); Azure/GCP remain US/EU list estimates. Public IPv4 (`$3.65/mo`/node) and boot EBS (`~$1.00–$1.60/mo`/node) have `$0` net delta after 1:1 replacement.

| Cloud / Option | Nodes | Current Monthly | Target Hardware TEE Monthly | **Net Monthly Delta** | Notes |
|---|---:|---:|---:|---:|---|
| **AWS — Option A (Recommended): `14 × c6g.large` (ARM64 Graviton2, 2 vCPU / 2 cores)** | 14 | **$891.86/mo** (`12 c6a.large` + `2 c6i.large`) | **$781.25/mo** (`us-east-1`: `$49.64/mo`) | **-$110.62/mo** | Nitro Enclaves `supported` in 14/14 regions (`1 vCPU` enclave + `1 vCPU` parent). Requires `arm64` binary + `arm64` `.eif` + AL2023 `arm64` parent AMI. (`14 × c7g.large` Graviton3: `$832.93/mo`, delta `-$58.93/mo`.) |
| **AWS — Option B (x86_64 Same-Family): `12 × c6a.xlarge` + `2 × c6i.xlarge`** | 14 | **$891.86/mo** | **$1,783.73/mo** (`us-east-1`: `$111.69/mo`) | **+$891.86/mo** (2.0×) | Zero arch change (`x86_64`, `2 vCPU` enclave + `2 vCPU` parent). Uniform `14 × c5a.xlarge` is `$1,763.68/mo` (`+$871.82/mo`); uniform `14 × c6i.xlarge` is `$1,999.03/mo` (`+$1,107.17/mo`). |
| **Azure** | 13–14 | `14× D2als_v7/v6/v4` (~$60–70/mo) ≈ **~$910/mo** | `13× DC2as_v6` (~$85–100/mo) + 1 `canadacentral` pending ≈ **~$1,250/mo** | **+$340/mo** | Confidential VM SKU premium ~25–35% over `D2als`. `canadacentral` blocked until subscription unlock. |
| **GCP (Published 14)** | 14 | `13× n2d-standard-2` (~$65/mo) + `1× e2-standard-2` (~$49/mo) ≈ **~$895/mo** | `13× n2d-standard-2 (SEV_SNP)` (~$70/mo) + `1× c3d-standard-4` (~$145/mo, if supported) ≈ **~$1,055/mo** | **+$160/mo** | `n2d-standard-2` SEV-SNP has near-zero surcharge over Gen-1 SEV; Querétaro `e2`->`c3d` adds ~$95/mo if available. |
| **GCP (Unpublished 8)** | 8 | Already running (`5× n2d-standard-2` + `3× c3-standard-4`) ≈ **~$835/mo** | **$0 additional compute** (already HW TEE!) | **$0/mo** | Enrolling these 8 adds 8 verified HW TEEs across NA/EU/Asia immediately at zero extra compute cost. |
| **TOTAL FLEET DELTA (with AWS Option A `c6g.large`)** | **42+8** | **~$3,532/mo** | **~$3,921/mo** | **+$389/mo** | Approval required before any AWS/Azure/GCP replacement. |
| **TOTAL FLEET DELTA (with AWS Option B `c6a/c6i.xlarge`)** | **42+8** | **~$3,532/mo** | **~$4,924/mo** | **+$1,392/mo** | Approval required before any AWS/Azure/GCP replacement. |

---

## 5. Phased Rollout & Acceptance Verification Plan (Zero Dev Fallback)

### Phase 0: Release Gates & Build Artifacts (Completed Locally)
- [x] Real AWS Nitro NSM attestation + COSE_Sign1 ES384 + pinned Root-G1 verification (`crates/pog-tee/src/aws_nitro.rs`).
- [x] Real host-to-enclave `AF_VSOCK` measurement/signing transport (`crates/pog-proto/src/vsock.rs`, `crates/pog-anchor`).
- [x] Fail-closed AMD SEV-SNP (VCEK/ASK/ARK P-384) & Intel TDX (DCAP PCK P-256) vendor-chain verification (`crates/pog-tee`).
- [x] Fail-closed `SoftwareDev` rejection across registry, `verify_proof_bundle`, SDKs, and CLI.
- [x] Automated release gate `scripts/release_gate.py` rejecting `--allow-dev-tee`, `--allow-dev-prover`, `SoftwareDev` anchors, missing `coordinate_basis`, and zero debug PCRs.
- [ ] Build signed deterministic Nitro `.eif` on an x86_64 Linux build host via `infra/images/build-nitro-eif.sh` and record pinned `(PCR0, PCR1, PCR2)` in release manifest.

### Phase 1: Tri-Cloud Hardware TEE Canaries (1 per Cloud, Strict Acceptance)
1. **GCP Canary (`gcp-europe-west3-frankfurt` SEV-SNP & `gcp-us-east4-ashburn` TDX — zero new spend):**
   - Deploy new `pog-anchor` WITHOUT `--allow-dev-tee` / `--allow-dev-prover`; verify `/dev/sev-guest` or `/dev/tdx_guest` quote chains cleanly to AMD ARK / Intel Root CA; attach audited `coordinate_basis`; enroll signed endorsement.
2. **AWS Canary (`aws-us-east-1-nvirginia` — requires Joseph's approval for 1 × `c6a.xlarge`):**
   - Launch blue-green `c6a.xlarge` with `enclave_options { enabled = true }`, `aws-nitro-enclaves-cli`, and measured `.eif` (`--cpu-count 2 --memory 1024`, NO `--debug-mode`).
   - Run `pog-anchor --nitro-host-relay --enclave-cid 16 --vsock-port 7443` on parent; verify `/info` returns COSE_Sign1 document signed by pinned AWS Nitro Root-G1 with non-zero matching `PCR0/1/2` and enclave-generated Ed25519 key.
3. **Azure Canary (`azure-eastus-virginia` — requires Joseph's approval for 1 × `Standard_DC2as_v6` AND coordinate fix to Ashburn/N. Virginia):**
   - Launch blue-green `Standard_DC2as_v6` (`ConfidentialVM`, SEV-SNP) with fixed `eastus` coordinates (`~39.04, -77.49`, verified via cross-cloud `c0` check against `aws-us-east-1` & `gcp-us-east4`!).
   - Verify `/dev/sev-guest` AMD VCEK/ASK/ARK chain + workload measurement.

### Phase 2: Canary Acceptance Gate (MANDATORY Before Fleet Rollout)
Every canary MUST pass ALL 5 tests with **ZERO dev fallback** (`--allow-dev-tee` forbidden):
1. **Cryptographic Chain & Policy:** `pog-cli network audit-live` passes with `hardware_attested = true`, `live_pk == published_pk == quote_pk == endorsement_pk`, non-zero `PCR0/1/2` (AWS) / `debug_disabled && migration_disabled` (SEV-SNP/TDX).
2. **Restart / Rotation Rejection:** Restart the enclave/VM -> confirm live ephemeral key changes -> confirm old endorsement is **rejected** (`stale endorsement` error) and old published key fails signature verification until fresh re-attestation & re-endorsement occur!
3. **Real-Network End-to-End Probe:** Probe canary over public UDP (`40000-40999`) from another cloud -> verify signed receipt verifies strictly inside the enclave/CVM and against published `pog-network.json`!
4. **Coordinate Provenance Audit:** Run cross-cloud `CalibrationMatrix::analyze()` -> confirm **0** speed-of-light violations (`> c0`) and record audited `coordinate_basis` (`source`, `uncertainty_km`, `audited_at_unix_s`, `hardware_identity_proves_coordinates = false`).
5. **Release Gate:** `python3 scripts/release_gate.py --registry <prod-registry.json> --eif-measurements <eif.json>` exits `0`.

### Phase 3: Blue-Green Fleet Rollout & Fail-Closed Production Cutoff
1. Roll out remaining 7 unpublished GCP HW TEE nodes + migrate 14 published GCP nodes (excluding any zone lacking `SEV_SNP`/`TDX` rather than downgrading to Gen-1 `SEV` or `SoftwareDev`).
2. Roll out remaining 13 AWS nodes (`c6a.xlarge` / `c6i.xlarge`) in regional waves (NA -> EU -> APAC/SA), keeping old nodes untouched until replacement passes Phase 2 checks.
3. Roll out remaining 12 unrestricted Azure CVM nodes (`Standard_DC2as_v6` / `DC2es_v6`); resolve `canadacentral` quota ticket (keep excluded from production registry while blocked).
4. Publish **new** production `/.well-known/pog-network.json` containing **ONLY** nodes that passed Phase 2 (`configured == reachable == attested == proof_eligible`), and isolate all legacy `SoftwareDev` nodes/demos into a clearly labeled diagnostic sandbox.
