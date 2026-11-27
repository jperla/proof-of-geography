# Reversible Operator-Run Vultr Honolulu (hnl / DRFortress, AS20473) Diagnostic Anchor
#
# Governance & Security Invariants:
# - Independent network / ASN (AS20473 at DRFortress HNL) distinct from AWS Local Zone (AS16509).
# - Diagnostic / SoftwareDev ONLY (Vultr hnl offers no public SEV-SNP/TDX Confidential VM SKU).
# - Uses existing operator Vultr account via VULTR_API_KEY env var (never creates a new account).
# - Reversible via `terraform destroy`.

data "vultr_os" "rocky_9" {
  count = var.enable_vultr_hnl ? 1 : 0
  filter {
    name   = "name"
    values = ["Rocky Linux 9 x64"]
  }
}

resource "vultr_ssh_key" "hnl" {
  count   = var.enable_vultr_hnl ? 1 : 0
  name    = "pog-diag-vultr-hnl-honolulu"
  ssh_key = var.ssh_public_key
}

resource "vultr_firewall_group" "hnl" {
  count       = var.enable_vultr_hnl ? 1 : 0
  description = "pog-isolated-fw-vultr-hnl-honolulu"
}

resource "vultr_firewall_rule" "hnl_ssh" {
  count             = var.enable_vultr_hnl && var.allow_ssh ? 1 : 0
  firewall_group_id = vultr_firewall_group.hnl[0].id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
  notes             = "Temporary bootstrap SSH only (disable immediately after setup)"
}

resource "vultr_firewall_rule" "hnl_https" {
  count             = var.enable_vultr_hnl && var.allow_https_443 ? 1 : 0
  firewall_group_id = vultr_firewall_group.hnl[0].id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
  notes             = "PoG HTTPS /info /ping (enabled only after DNS + TLS setup)"
}

resource "vultr_firewall_rule" "hnl_tcp_7443" {
  count             = var.enable_vultr_hnl ? 1 : 0
  firewall_group_id = vultr_firewall_group.hnl[0].id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "7443"
  notes             = "PoG Phase 1 TCP handshake"
}

resource "vultr_firewall_rule" "hnl_http_7445" {
  count             = var.enable_vultr_hnl ? 1 : 0
  firewall_group_id = vultr_firewall_group.hnl[0].id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "7445"
  notes             = "PoG HTTP /info /attest metadata"
}

resource "vultr_firewall_rule" "hnl_udp_range" {
  count             = var.enable_vultr_hnl ? 1 : 0
  firewall_group_id = vultr_firewall_group.hnl[0].id
  protocol          = "udp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "40000:40999"
  notes             = "PoG Phase 2 UDP distance-bounding challenge range"
}

resource "vultr_instance" "hnl" {
  count             = var.enable_vultr_hnl ? 1 : 0
  plan              = var.vultr_plan
  region            = var.vultr_region
  os_id             = data.vultr_os.rocky_9[0].id
  label             = "vultr-hnl-honolulu"
  hostname          = "vultr-hnl-honolulu"
  enable_ipv6       = true
  ddos_protection   = false
  backups           = "disabled"
  firewall_group_id = vultr_firewall_group.hnl[0].id
  ssh_key_ids       = [vultr_ssh_key.hnl[0].id]
  tags = [
    "proof-of-geography",
    "diagnostic-only",
    "tee-mode:software-dev",
    "failure-domain:vultr-hnl-drfortress-as20473",
    "asn:20473"
  ]

  user_data = templatefile("${path.module}/cloud-init-honolulu.yaml", {
    anchor_id              = "vultr-hnl-honolulu"
    cloud_provider         = "vultr"
    failure_domain         = "vultr-hnl-drfortress/AS20473"
    release_tarball_url    = var.release_tarball_url
    release_tarball_sha256 = var.release_tarball_sha256
    ssh_public_key         = var.ssh_public_key
    extra_flags            = "--allow-dev-tee --allow-dev-prover"
  })

  lifecycle {
    ignore_changes = [user_data]
  }
}
