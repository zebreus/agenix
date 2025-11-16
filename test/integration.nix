{
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  home-manager ? <home-manager>,
}:
pkgs.nixosTest {
  name = "agenix-integration";
  nodes.system1 =
    {
      config,
      pkgs,
      options,
      ...
    }:
    {
      imports = [
        ../modules/age.nix
        ./install_ssh_host_keys.nix
        "${home-manager}/nixos"
      ];

      services.openssh.enable = true;

      age.secrets = {
        passwordfile-user1.file = ./example/passwordfile-user1.age;
        leading-hyphen.file = ./example/-leading-hyphen-filename.age;
      };

      age.identityPaths = options.age.identityPaths.default ++ [ "/etc/ssh/this_key_wont_exist" ];

      users = {
        mutableUsers = false;

        users = {
          user1 = {
            isNormalUser = true;
            hashedPasswordFile = config.age.secrets.passwordfile-user1.path;
            uid = 1000;
          };
        };
      };

      home-manager.users.user1 =
        { options, ... }:
        {
          imports = [
            ../modules/age-home.nix
          ];

          home.stateVersion = pkgs.lib.trivial.release;

          age = {
            identityPaths = options.age.identityPaths.default ++ [ "/home/user1/.ssh/this_key_wont_exist" ];
            secrets.secret2 = {
              # Only decryptable by user1's key
              file = ./example/secret2.age;
            };
            secrets.secret2Path = {
              file = ./example/secret2.age;
              path = "/home/user1/secret2";
            };
            secrets.armored-secret = {
              file = ./example/armored-secret.age;
            };
          };
        };
    };

  testScript =
    let
      user = "user1";
      password = "password1234";
      secret2 = "world!";
      hyphen-secret = "filename started with hyphen";
      armored-secret = "Hello World!";
    in
    ''
      # This test focuses on the NixOS and home-manager modules' ability
      # to decrypt and mount secrets. CLI-specific tests are in test/cli.nix.

      system1.wait_for_unit("multi-user.target")
      system1.wait_until_succeeds("pgrep -f 'agetty.*tty1'")
      system1.sleep(2)
      system1.send_key("alt-f2")
      system1.wait_until_succeeds("[ $(fgconsole) = 2 ]")
      system1.wait_for_unit("getty@tty2.service")
      system1.wait_until_succeeds("pgrep -f 'agetty.*tty2'")
      system1.wait_until_tty_matches("2", "login: ")
      system1.send_chars("${user}\n")
      system1.wait_until_tty_matches("2", "login: ${user}")
      system1.wait_until_succeeds("pgrep login")
      system1.sleep(2)
      system1.send_chars("${password}\n")
      system1.send_chars("whoami > /tmp/1\n")
      system1.wait_for_file("/tmp/1")
      assert "${user}" in system1.succeed("cat /tmp/1")

      # Test home-manager module: user secret should be decrypted at expected path
      system1.send_chars("cat /run/user/$(id -u)/agenix/secret2 > /tmp/2\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/2")
      system1.sleep(8)
      assert "${secret2}" in system1.succeed("cat /tmp/2")

      # Test home-manager module: armored secret should be decrypted
      system1.send_chars("cat /run/user/$(id -u)/agenix/armored-secret > /tmp/3\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/3")
      system1.sleep(5)
      assert "${armored-secret}" in system1.succeed("cat /tmp/3")

      # Test NixOS module: system secret with leading hyphen in filename
      assert "${hyphen-secret}" in system1.succeed("cat /run/agenix/leading-hyphen")

      # Test home-manager module: custom path for secret
      system1.send_chars("cat /home/user1/secret2 > /tmp/4\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/4")
      system1.sleep(5)
      assert "${secret2}" in system1.succeed("cat /tmp/4")
    '';
}
