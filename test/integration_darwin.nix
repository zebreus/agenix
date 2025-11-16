{
  darwin,
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  home-manager ? <home-manager>,
}:
(darwin.lib.darwinSystem {
  inherit system;
  modules = [
    (
      {
        config,
        pkgs,
        options,
        ...
      }:
      let
        secret = "hello";
        testScript = pkgs.writeShellApplication {
          name = "agenix-integration";
          text = ''
            grep "${secret}" "${config.age.secrets.system-secret.path}"
          '';
        };
      in
      {
        imports = [
          home-manager.darwinModules.home-manager
          ./install_ssh_host_keys_darwin.nix
          ../modules/age.nix
        ];

        home-manager = {
          verbose = true;
          useGlobalPkgs = true;
          useUserPackages = true;
          backupFileExtension = "hmbak";
          users.runner = ./integration_hm_darwin.nix;
        };

        age = {
          identityPaths = options.age.identityPaths.default ++ [ "/etc/ssh/this_key_wont_exist" ];
          secrets.system-secret.file = ../example/secret1.age;
        };

        environment.systemPackages = [ testScript ];

        # We activate this system in CI so we want to ensure the same features are
        # enabled there as well.
        nix.settings = {
          system-features = [
            "nixos-test"
            "recursive-nix"
            "benchmark"
            "big-parallel"
            "kvm"
          ];
          experimental-features = [
            "recursive-nix"
            "nix-command"
            "flakes"
          ];
        };

        system.stateVersion = 6;
      }
    )
  ];
}).system
