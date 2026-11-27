{
  description = "Reproducible, immutable, zero-SSH NixOS Confidential VM image for Proof of Geography Anchors (deterministic AMD SEV-SNP / Intel TDX measurement)";

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
          ({ pkgs, lib, ... }: {
            system.stateVersion = "24.11";
            boot.kernelPackages = pkgs.linuxPackages_latest;
            boot.kernelParams = [
              "isolcpus=1"
              "nohz_full=1"
              "rcu_nocbs=1"
              "sev=on"
              "systemd.debug_shell=0"
              "rd.shell=0"
              "rd.emergency=halt"
            ];
            boot.kernel.sysctl = {
              "net.core.busy_poll" = 50;
              "net.core.busy_read" = 50;
              "net.core.rmem_max" = 16777216;
              "net.core.wmem_max" = 16777216;
              "kernel.kptr_restrict" = 2;
              "kernel.dmesg_restrict" = 1;
            };

            # Measured Zero-SSH / Zero-Interactive-Admin-Shell Policy:
            # Substantiated inside the measured immutable rootfs + kernel cmdline (NOT just a closed firewall port!):
            # 1. No SSH server (`openssh` omitted and disabled).
            # 2. No local/serial interactive console getty shells (`getty@tty1`, `serial-getty@ttyS0`, emergency shell disabled).
            # 3. No mutable users, no sudo, no cloud metadata remote-exec / OS-Login / SSM / guest-agent command channel.
            services.openssh.enable = false;
            users.mutableUsers = false;
            security.sudo.enable = false;
            systemd.services."serial-getty@ttyS0".enable = false;
            systemd.services."getty@tty1".enable = false;
            systemd.services."autovt@".enable = false;
            systemd.services."emergency".enable = false;
            systemd.services."rescue".enable = false;
            boot.initrd.systemd.emergencyAccess = false;

            networking.firewall = {
              enable = true;
              allowedTCPPorts = [ 443 7443 7445 ];
              allowedUDPPortRanges = [ { from = 40000; to = 40999; } ];
            };

            # Production hardware-TEE daemon ONLY (NEVER passes --allow-dev-tee or --allow-dev-prover!)
            systemd.services.pog-anchor = {
              description = "Proof of Geography Measured Zero-SSH Anchor TEE Daemon";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = "/usr/local/bin/pog-anchor --tcp-listen 0.0.0.0:7443 --udp-bind 0.0.0.0:7444 --udp-port-min 40000 --udp-port-max 40999 --http-info-listen 0.0.0.0:7445";
                Restart = "always";
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                ReadOnlyPaths = [ "-/etc/pog" ];
                ReadWritePaths = [ "-/dev/sev-guest" "-/dev/tdx_guest" "-/sys/kernel/config/tsm/report" ];
                CPUSchedulingPolicy = "fifo";
                CPUSchedulingPriority = 50;
              };
            };
          })
        ];
      };
    };
}
