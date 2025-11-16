{
  darwin,
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  home-manager ? <home-manager>,
}:
let
  integrate_me =
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
        ./install_ssh_host_keys_darwin.nix
        ../modules/age.nix
      ];

      age = {
        identityPaths = options.age.identityPaths.default ++ [ "/etc/ssh/this_key_wont_exist" ];
        secrets.system-secret.file = ../example/secret1.age;
      };

      environment.systemPackages = [ testScript ];

      system.stateVersion = 6;
    };
in
(darwin.lib.darwinSystem {
  inherit system;
  modules = [
    integrate_me

    # Allow new-style nix commands in CI
    { nix.extraOptions = "experimental-features = nix-command flakes"; }

    home-manager.darwinModules.home-manager
    {
      home-manager = {
        verbose = true;
        useGlobalPkgs = true;
        useUserPackages = true;
        backupFileExtension = "hmbak";
        users.runner = ./integration_hm_darwin.nix;
      };
    }
  ];
}).system
