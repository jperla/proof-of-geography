# Reversible Two-Provider Honolulu Diagnostic Anchor Stack

This isolated Terraform stack provisions **two operator-run, diagnostic-only Honolulu anchors on independent networks** without touching `infra/terraform/pilot/`, Frankfurt, or the live 42-node public roster:

| Anchor ID | Provider & Region | Network / Failure Domain | Recommended SKU | Exact Monthly Cost (USD) | TEE Status |
|---|---|---|---|---|---|
| `aws-us-west-2-hnl-honolulu` | AWS Local Zone `us-west-2-hnl-1a` (`us-west-2` parent) | `aws-us-west-2-hnl-1a/AS16509` | `t3.medium` (2 vCPU, 4 GiB) + `10 GB gp2` + `1 EIP` | **`$53.34/mo`** fixed (`$47.09` compute + `$2.60` gp2 @ `$0.26/GB` + `$3.65` IPv4) + `$0.09/GB` Internet egress (`$0.032/GB` to `us-west-2`) | **`SoftwareDev` / `diagnostic_only: true`** (AWS Local Zones do **not** support Nitro Enclaves or SEV-SNP) |
| `vultr-hnl-honolulu` | Vultr `hnl` (DRFortress HNL) | `vultr-hnl-drfortress/AS20473` | `vhp-1c-2gb-intel` (or `vhp-1c-1gb-intel` `$6/mo` / `voc-c-1c-2gb-25s-amd` `$28/mo`) | **`$12.00/mo`** all-inclusive (`3 TB` egress + 1 IPv4 + 50 GB NVMe; `$0.01/GB` overage) | **`SoftwareDev` / `diagnostic_only: true`** (Vultr `hnl` lists no SEV-SNP/TDX Confidential VM SKU) |
| **Aggregate Pair** | **2 Independent Providers** | **2 Distinct ASNs (`AS16509`, `AS20473`)** | `t3.medium` + `vhp-1c-2gb-intel` | **`$65.34/mo` fixed** (`~$66–$70/mo` with `10–50 GB` AWS egress; `$59.34/mo` fixed with `vhp-1c-1gb-intel`; `$81.34/mo` fixed with dedicated AMD `voc`) | **Strictly excluded from production hardware proof quorum** |

## Pre-Apply Requirements (Operator Approval Required)
1. **AWS Local Zone Opt-In (one-time scoped action on account `330422590279`):**
   ```bash
   aws ec2 modify-availability-zone-group \
     --region us-west-2 \
     --group-name us-west-2-hnl-1 \
     --opt-in-status opted-in
   ```
2. **Existing Operator Vultr API Key (do NOT create a new account or payment method):**
   ```bash
   export VULTR_API_KEY="<existing-operator-vultr-api-key>"
   ```
3. **Bootstrap & Apply (isolated state inside `infra/terraform/honolulu/`):**
   ```bash
   cp terraform.tfvars.example terraform.tfvars   # gitignored
   # Step 1: initial bootstrap with lockdown_egress=false (so cloud-init pulls static musl tarball)
   terraform init
   terraform plan -var="lockdown_egress=false"
   terraform apply -var="lockdown_egress=false"
   # Step 2: lock down egress + disable IMDS once pog-anchor is active
   terraform apply -var="lockdown_egress=true" -var="allow_ssh=false"
   ```

## Post-Boot Verification & Diagnostic-Only Enrollment
```bash
# Verify distinct ephemeral keys, verified on-island endpoints, live signed UDP receipts from another vantage,
# non-hairpin latency checks, and strict exclusion from production hardware proof quorum:
python3 ../../../scripts/verify_honolulu_addition.py \
  --live \
  --aws-url "http://<AWS_HNL_EIP>:7445" \
  --aws-tcp "<AWS_HNL_EIP>:7443" \
  --vultr-url "http://<VULTR_HNL_IP>:7445" \
  --vultr-tcp "<VULTR_HNL_IP>:7443"
```
Both nodes carry `tee_vendor: "SoftwareDev"` and `diagnostic_only: true`, so:
- `pog-cli network verify-registry --allow-dev-anchors` accepts them in the diagnostic roster.
- `pog-cli network verify-registry` (production default), `select_committee` (`allow_software_dev_anchors: false`), `verify_proof_bundle` (`AttestationPolicy::production()`), `scripts/release_gate.py --authorize-promotion`, and `web/constellation.js` (`hwTee === 0`, `officialProofEligible === 0`) **all fail-closed exclude them from the production proof quorum**.

## Reversible Rollback
```bash
# 1. Destroy both Honolulu VMs, isolated VPC, EIP, and Vultr firewall group (zero effect on pilot fleet/Frankfurt):
terraform destroy

# 2. Optional: revert AWS Honolulu Local Zone opt-in if no longer needed:
aws ec2 modify-availability-zone-group \
  --region us-west-2 \
  --group-name us-west-2-hnl-1 \
  --opt-in-status not-opted-in

# 3. Revert any staged diagnostic registry diff back to the exact 42-node baseline:
git checkout -- config/public_anchors.json web/data/anchors.json
```
