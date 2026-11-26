{
  description = "Reproducible measured NixOS Confidential VM image for Proof of Geography Anchors & Provers (deterministic SEV-SNP / Intel TDX launch digest)"

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      nixosConfigurations.pog-anchor-tee = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ({ pkgs, ... }: {
            system.stateVersion = "24.11";
            boot.kernelPackages = pkgs.linuxPackages_latest;
            boot.kernelParams = [
              "console=ttyS0"
              "isolcpus=1"
              "nohz_full=1"
              "rcu_nocbs=1"
              "sev=on"
            ];
            boot.kernel.sysctl = {
              "net.core.busy_poll" = 50;
              "net.core.busy_read" = 50;
              "net.core.rmem_max" = 16777216;
              "net.core.wmem_max" = 16777216;
            };
            # Immutable root + no SSH daemon in production TEE images so host/operator cannot inject code!
            services.openssh.enable = false;
            networking.firewall = {
              enable = true;
              allowedTCPPorts = [ 7443 ];
              allowedUDPPortRanges = [ { from = 7444; to = 65535; } ];
            };
            systemd.services.pog-anchor = {
              description = "Proof of Geography Anchor TEE Daemon";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = "/usr/local/bin/pog-anchor --tcp-listen 0.0.0.0:7443 --udp-bind 0.0.0.0:7444";
                Restart = "always";
                CPUSchedulingPolicy = "fifo";
                CPUSchedulingPriority = 50;
              };
            };
          })
        ];
      };
    };
}
