{
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  home-manager ? <home-manager>,
}:
pkgs.testers.nixosTest {
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

      # Set secretsPath to use example directory
      age.secretsPath = ./example;

      age.secrets = {
        passwordfile-user1 = { };
        leading-hyphen = { };
        # Test secret files that correspond to publics defined below
        secret-with-public = { };
        "secret-with-public-custom-path" = {
          name = "secret-with-public";
        };
        "secret-with-public-copy" = {
          name = "secret-with-public";
        };
        "ssh-host-key" = {
          name = "secret-with-public";
          path = "/etc/ssh/ssh_host_ed25519_key_test";
          mode = "0600";
        };
        "deploy-key" = {
          name = "secret-with-public";
          path = "/var/lib/deploy/.ssh/id_ed25519";
          mode = "0400";
          owner = "root";
        };
      };

      # NEW: Public files configuration at top-level
      age.publics = {
        # Test public file using installPath
        secret-with-public = {
          file = ./example/secret-with-public.pub;
          installPath = "/run/agenix-public/secret-with-public.pub";
        };
        # Test public file at custom path with permissions
        secret-with-public-custom-path = {
          file = ./example/secret-with-public.pub;
          installPath = "/etc/my-public-key.pub";
          mode = "0644";
          owner = "root";
          group = "root";
        };
        # Test public file without symlink (copy mode)
        secret-with-public-copy = {
          file = ./example/secret-with-public.pub;
          installPath = "/etc/my-public-key-copy.pub";
          symlink = false;
          mode = "0600";
        };
        # Real-world scenario: SSH host key with public key
        ssh-host-key = {
          file = ./example/secret-with-public.pub;
          installPath = "/etc/ssh/ssh_host_ed25519_key_test.pub";
          mode = "0644";
        };
        # Real-world scenario: Deploy key with public part for authorized_keys
        deploy-key = {
          file = ./example/secret-with-public.pub;
          installPath = "/var/lib/deploy/.ssh/id_ed25519.pub";
          mode = "0444";
          owner = "root";
        };
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
        { options, config, ... }:
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
            # Test secret files that correspond to publics defined below
            secrets.hm-secret-with-public.file = ./example/secret-with-public.age;
            secrets.hm-secret-with-public-custom.file = ./example/secret-with-public.age;
            secrets.hm-user-ssh-key = {
              file = ./example/secret-with-public.age;
              path = "/home/user1/.ssh/id_ed25519_test";
              mode = "0600";
            };

            # NEW: Home-manager publics at top-level
            publics = {
              # Test home-manager public file symlinking using installPath
              hm-secret-with-public = {
                file = ./example/secret-with-public.pub;
                installPath = "${config.age.publicKeysDir}/hm-secret-with-public.pub";
              };
              # Test home-manager public file at custom path
              hm-secret-with-public-custom = {
                file = ./example/secret-with-public.pub;
                installPath = "/home/user1/.config/my-public-key.pub";
                mode = "0644";
              };
              # Real-world scenario: User SSH key with public part
              hm-user-ssh-key = {
                file = ./example/secret-with-public.pub;
                installPath = "/home/user1/.ssh/id_ed25519_test.pub";
                mode = "0644";
              };
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
      public-content = "my-public-key-content";
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

      # Test NixOS module: public file at default location (symlink)
      assert "${public-content}" in system1.succeed("cat /run/agenix-public/secret-with-public.pub")

      # Verify it's a symlink
      system1.succeed("test -L /run/agenix-public/secret-with-public.pub")

      # Test NixOS module: public file at custom path
      assert "${public-content}" in system1.succeed("cat /etc/my-public-key.pub")

      # Verify it's a symlink  
      system1.succeed("test -L /etc/my-public-key.pub")

      # Test NixOS module: public file in copy mode (not a symlink)
      assert "${public-content}" in system1.succeed("cat /etc/my-public-key-copy.pub")

      # Verify it's NOT a symlink (regular file)
      system1.succeed("test -f /etc/my-public-key-copy.pub && ! test -L /etc/my-public-key-copy.pub")

      # Test home-manager module: public file at default location
      system1.send_chars("cat /run/user/$(id -u)/agenix-public/hm-secret-with-public.pub > /tmp/5\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/5")
      system1.sleep(5)
      assert "${public-content}" in system1.succeed("cat /tmp/5")

      # Test home-manager module: public file at custom path
      system1.send_chars("cat /home/user1/.config/my-public-key.pub > /tmp/6\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/6")
      system1.sleep(5)
      assert "${public-content}" in system1.succeed("cat /tmp/6")

      # Real-world scenario tests:

      # Test NixOS: SSH host key pair (private + public)
      assert "${public-content}" in system1.succeed("cat /etc/ssh/ssh_host_ed25519_key_test.pub")
      system1.succeed("test -f /etc/ssh/ssh_host_ed25519_key_test")
      # Verify public key is a symlink (the default)
      system1.succeed("test -L /etc/ssh/ssh_host_ed25519_key_test.pub")

      # Test NixOS: Deploy key pair
      assert "${public-content}" in system1.succeed("cat /var/lib/deploy/.ssh/id_ed25519.pub")
      system1.succeed("test -f /var/lib/deploy/.ssh/id_ed25519")

      # Test Home Manager: User SSH key pair
      system1.send_chars("cat /home/user1/.ssh/id_ed25519_test.pub > /tmp/7\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/7")
      system1.sleep(5)
      assert "${public-content}" in system1.succeed("cat /tmp/7")
      # Verify the private key also exists
      system1.send_chars("test -f /home/user1/.ssh/id_ed25519_test && echo 'exists' > /tmp/8\n")
      system1.sleep(2)
      system1.wait_for_file("/tmp/8")
      assert "exists" in system1.succeed("cat /tmp/8")
    '';
}
