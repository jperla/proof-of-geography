# Multi-Operator Federation & Local Root-Key PKI

Proof of Geography is designed as an **open, federated, Apache-2.0 protocol** — never a single centralized monopoly. **The official `proofofgeography.com` constellation contains ONLY nodes operated by Proof of Geography** (we do not add third-party nodes to the official registry, maintain a community admission PR workflow, or mix external nodes into official proofs or official hardware counts).

Instead, any independent operator (Cloudflare, OVHcloud, EFF, a university consortium, or your own team) can self-host their own separate constellation, sign their own registry under their own root key, expose their own HTTPS `/info`, `/attest`, and `/ping` endpoints via optional `https_url`, and inspect that separate constellation on the map via `?registry=<url>`. Relying-party SDKs can also require quorum across `X` independent constellations (`minIndependentNetworks = 2` or `3`) before trusting a GPU or datacenter's physical location.

---

## Self-Hosting Your Own Constellation (`?registry=<url>`)

See the minimal working template in [examples/external_constellation_registry.json](../examples/external_constellation_registry.json).

```bash
# 1. Generate your own offline operator root key (never shared with proofofgeography.com)
pog-cli network init \
  --network-id pog.example-operator.org \
  --operator "Example Independent Operator" \
  --key-out ~/.pog/example-root.key

# 2. Prepare your grid JSON with optional per-anchor `https_url` pointing to YOUR HTTPS endpoints
#    (each endpoint serves CORS-enabled `/info`, `/attest?nonce=<hex>`, and `/ping`)
# 3. Sign your registry under your own root key:
pog-cli network sign-registry \
  --key ~/.pog/example-root.key \
  --network-id pog.example-operator.org \
  --operator "Example Independent Operator" \
  --grid my_grid.json \
  --out ./pog-network.json \
  --ttl-days 90

# 4. Publish `./pog-network.json` over HTTPS with CORS (`Access-Control-Allow-Origin: *`),
#    then open the map pointed strictly at YOUR separate constellation:
#    https://proofofgeography.com/?registry=https://pog.example-operator.org/.well-known/pog-network.json
```

> **Strict Separation:** `?registry=<url>` **replaces** the active map constellation with your external registry rather than merging it with `web/data/anchors.json`. The UI labels it **Independently Operated**, counts attested hardware (`Intel TDX`, `AMD SEV-SNP`, `AWS Nitro`) only within the selected constellation, and never treats hardware verification on an external constellation as official Proof of Geography membership.

---

## Security Architecture: Root Key Stays Strictly Offline / Local

A critical operational rule of Proof of Geography:

> **Your master Ed25519 root private key NEVER touches a cloud Anchor VM.**

Instead, the operator's local workstation (or HSM) signs two lightweight artifacts:

1. **`SignedNetworkRegistry` (`/.well-known/pog-network.json`):**
   A canonical SHA-256 (`POG-NETWORK-REGISTRY-V1`) + Ed25519 signature over the operator's `network_id`, `operator_name`, `issued_at_unix_s`, `expires_at_unix_s`, and every Anchor's `{anchor_id, cloud_provider, region, lat, lon, endpoint_tcp, public_key_hex}`.
   * Tampering with **even one coordinate or one Anchor public key** invalidates the operator signature immediately in Rust, TypeScript, Python, and Go.
2. **Per-Anchor `AnchorEndorsement` Certificates (`POG-ANCHOR-ENDORSEMENT-V1`):**
   Individually signed per-node certificates secretly provisioned to each Anchor VM (`pog-anchor --endorsement-path /etc/pog/endorsement.json` or `POG_ENDORSEMENT_PATH`). Each Anchor publishes its own endorsement on `/info` without ever possessing the root private key — so compromising one cloud VM can **never** mint rogue Anchors for the rest of the network.

---

## Operator Quickstart (Signing Your Own Network)

```bash
# 1. Generate your master Ed25519 root private key strictly on your local computer (chmod 0600, OUTSIDE git!)
./target/release/pog-cli network init \
  --network-id my-org-pog.example \
  --operator "My Org" \
  --key-out ~/.pog/networks/my-org-root.key

# 2. Sign your Anchor grid (e.g., 40–72+ global Anchors) -> publish at https://my-org.example/.well-known/pog-network.json
./target/release/pog-cli network sign-registry \
  --key ~/.pog/networks/my-org-root.key \
  --network-id my-org-pog.example \
  --operator "My Org" \
  --grid config/public_anchors.json \
  --out config/signed_my_org_network.json \
  --ttl-days 365

# 3. Generate per-Anchor endorsement certs and secretly send ONLY each node's cert to that VM
./target/release/pog-cli network endorse-anchors \
  --key ~/.pog/networks/my-org-root.key \
  --network-id my-org-pog.example \
  --grid config/public_anchors.json \
  --out-dir ~/.pog/endorsements/ \
  --ttl-days 365

# 4. Verify the published SignedNetworkRegistry offline against your pinned root public key
./target/release/pog-cli network verify-registry \
  --signed-registry config/signed_my_org_network.json \
  --pinned-root-pk <YOUR_PINNED_ROOT_PUBLIC_KEY_HEX>
```

---

## Querying `X` Independent Networks in the SDKs

Relying parties pin ONLY the 32-byte Ed25519 root public key of each independent operator they trust (for example, `proofofgeography.com` + `cloudflare-pog` + `ovh-pog`). Every SDK enforces:

* **Distinct Root Key Independence:** Two network aliases sharing the same root public key are rejected as non-independent — they cannot satisfy `minIndependentNetworks = 2`.
* **Cross-Network Prover TEE Binding:** All `X` networks must observe the **exact same Prover TEE `public_key_hex`** (stopping split-TEE / multi-host relay collusion).
* **Cross-Network External IP Consistency:** Every Anchor signs `prover_observed_ip` inside its `AnchorReceipt`. Both single-network (`observedProverIps`, `distinctObservedIps`, `ipViewConsistent`) and multi-network (`observedProverIpsAcrossNetworks`, `ipConsistentAcrossNetworks`) reports expose what external IP(s) the Anchors observed — immediately flagging Anycast front-ends or split egress routing.

### TypeScript (Zero Dependencies)

```ts
import { queryFederatedNetworks } from "@proof-of-geography/verifier";

const report = await queryFederatedNetworks(
  [
    {
      networkId: "proofofgeography.com",
      registryUrl: "https://proofofgeography.com/.well-known/pog-network.json",
      pinnedRootPublicKeyHex: "fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1",
    },
    {
      networkId: "cloudflare-pog",
      registryUrl: "https://pog.cloudflare.example/.well-known/pog-network.json",
      pinnedRootPublicKeyHex: "<cloudflare-pinned-ed25519-root-pk>",
    },
  ],
  [
    { networkId: "proofofgeography.com", bundleOrHeader: req.headers["x-pog-proof-pog"] },
    { networkId: "cloudflare-pog", bundleOrHeader: req.headers["x-pog-proof-cf"] },
  ],
  { minIndependentNetworks: 2 }
);

console.log({
  valid: report.overallValid,
  operators: report.distinctOperatorsVerified,
  observedIps: report.observedProverIpsAcrossNetworks,
  ipConsistent: report.ipConsistentAcrossNetworks,
  consensusFiberKm: report.consensusTier1bFiberKm,
});
```

### Python (Zero Dependencies)

```python
from pog_verifier import NetworkSource, query_federated_networks

report = query_federated_networks(
    sources=[
        NetworkSource(
            network_id="proofofgeography.com",
            registry_url="https://proofofgeography.com/.well-known/pog-network.json",
            pinned_root_public_key_hex="fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1",
        ),
        NetworkSource(
            network_id="cloudflare-pog",
            registry_url="https://pog.cloudflare.example/.well-known/pog-network.json",
            pinned_root_public_key_hex="<cloudflare-pinned-ed25519-root-pk>",
        ),
    ],
    submissions=[
        ("proofofgeography.com", pog_header),
        ("cloudflare-pog", cf_header),
    ],
    min_independent_networks=2,
)
print(report.overall_valid, report.distinct_operators_verified, report.observed_prover_ips_across_networks)
```

### Go (Zero Dependencies)

```go
report := pog.QueryFederatedNetworks(
    []pog.NetworkSource{
        {
            NetworkID:              "proofofgeography.com",
            RegistryURL:            "https://proofofgeography.com/.well-known/pog-network.json",
            PinnedRootPublicKeyHex: "fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1",
        },
        {
            NetworkID:              "cloudflare-pog",
            RegistryURL:            "https://pog.cloudflare.example/.well-known/pog-network.json",
            PinnedRootPublicKeyHex: "<cloudflare-pinned-ed25519-root-pk>",
        },
    },
    submissions,
    pog.VerificationPolicy{MinAnchors: 4, MinCloudProviders: 2, MaxByzantine: 1},
    2, // require X = 2 independent operator networks
    uint64(time.Now().Unix()),
    nil,
)
```
