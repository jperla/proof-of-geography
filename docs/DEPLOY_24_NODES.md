# Deploying the Live 24-Node Global Anchor Grid & Public Playground

The repository contains complete, runnable daemons and multi-cloud Terraform templates—**no live cloud VMs are running yet until you apply Terraform with your own cloud credentials.**

## 1. Try Everything Locally First (Free, 10 Seconds)
```bash
./scripts/live_smoke_test.sh
# Open http://127.0.0.1:8090 in your browser for the interactive Anchor Map & X-PoG-Proof Verifier!
```

## 2. Deploy the Live 24-Node Multi-Cloud Grid
1. Authenticate your cloud CLIs:
   ```bash
   gcloud auth application-default login
   aws configure
   az login
   ```
2. Build & publish static Linux `pog-anchor` binary (or NixOS TEE image via `infra/images/flake.nix` / Nitro `.eif` via `infra/images/build-nitro-eif.sh`).
3. Provision GCP (8) + AWS (8) + Azure (4) = 20 Confidential VMs and automatically collect their hardware-attested Ed25519 keys:
   ```bash
   ./scripts/deploy_24_grid.sh <YOUR_GCP_PROJECT> <YOUR_AZURE_SUBSCRIPTION_ID>
   ```
4. Provision the remaining 4 sovereign/Asian diversity nodes via `infra/terraform/modules/{ovh,bytedance,tencent}-anchor/` and append their `/info` outputs to `config/global_grid_live.json`.
5. Launch the public DNS/CT transparency log & web playground behind HTTPS (Caddy/Cloudflare/nginx):
   ```bash
   pog-cli serve-log --grid config/global_grid_live.json --listen 0.0.0.0:8090
   ```
   Public users can then:
   - Browse the interactive map & paste `X-PoG-Proof` headers at `https://pog.yourdomain.com/`
   - Fetch the signed public Anchor registry at `https://pog.yourdomain.com/.well-known/pog-registry`
   - Verify any endpoint offline in **Rust, TypeScript, Python, or Go** (`sdks/`)!
