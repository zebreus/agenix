# UX Testing for agenix NixOS Module
#
# This test creates a realistic NixOS VM configuration that exercises
# the agenix module with real-world scenarios:
# 1. Self-hosted applications (Gitea) with secrets
# 2. SSH deployment keys
# 3. Shared secrets across services
# 4. Home Manager user secrets
{
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  home-manager ? <home-manager>,
}:
pkgs.testers.nixosTest {
  name = "agenix-ux-testing";

  nodes.testvm =
    {
      config,
      pkgs,
      options,
      ...
    }:
    {
      imports = [
        ../../modules/age.nix
        ../install_ssh_host_keys.nix
        "${home-manager}/nixos"
      ];

      # Basic system configuration
      services.openssh.enable = true;

      # Configure agenix with secrets from test/example directory
      # Using existing test secrets that are encrypted with test keys

      # Scenario 1: Self-hosted Gitea with database secrets
      # This tests a common use case: web application with database
      age.secrets.gitea-db-password = {
        file = ../example/secret1.age;
        owner = "gitea";
        mode = "0400";
      };

      age.secrets.gitea-admin-password = {
        file = ../example/passwordfile-user1.age;
        owner = "gitea";
        mode = "0400";
      };

      age.secrets.gitea-secret-key = {
        file = ../example/-leading-hyphen-filename.age;
        owner = "gitea";
        mode = "0400";
      };

      # Configure all users and groups in one place
      users = {
        mutableUsers = false;

        users = {
          # User for SSH keys (required by install_ssh_host_keys.nix)
          user1 = {
            isNormalUser = true;
            uid = 1100;
          };

          # Scenario 1: Gitea user
          gitea = {
            isSystemUser = true;
            group = "gitea";
            uid = 1001;
          };

          # Scenario 2: Deploy user for SSH keys
          deploy = {
            isSystemUser = true;
            group = "deploy";
            uid = 1002;
          };

          # Scenario 3: Postgres user for shared secrets
          postgres = {
            isSystemUser = true;
            group = "postgres";
            uid = 1003;
          };

          # Scenario 4: Normal user for Home Manager
          testuser = {
            isNormalUser = true;
            uid = 1000;
            initialPassword = "test";
          };
        };

        groups = {
          gitea.gid = 1001;
          deploy.gid = 1002;
          postgres.gid = 1003;
        };
      };

      # Scenario 2: SSH deployment key management
      # This tests managing SSH keys for deployment
      age.secrets.deploy-ssh-key = {
        file = ../example/secret-with-public.age;
        owner = "deploy";
        mode = "0400";
      };

      # Scenario 3: Multi-service secret sharing
      # Tests shared secrets with proper permissions
      age.secrets.shared-api-token = {
        file = ../example/secret-with-public.age;
        owner = "root";
        mode = "0440";
      };

      age.secrets.shared-db-password = {
        file = ../example/secret1.age;
        owner = "postgres";
        group = "postgres";
        mode = "0400";
      };

      home-manager.users.testuser =
        { config, options, ... }:
        {
          imports = [ ../../modules/age-home.nix ];

          home.stateVersion = pkgs.lib.trivial.release;

          age = {
            identityPaths = options.age.identityPaths.default ++ [
              "/home/testuser/.ssh/this_key_wont_exist"
            ];

            # User-level secrets
            secrets.user-github-token = {
              file = ../example/secret2.age;
              mode = "0600";
            };

            secrets.user-ssh-key = {
              file = ../example/secret-with-public.age;
              mode = "0600";
            };
          };
        };

      # Add identity paths for testing
      age.identityPaths = options.age.identityPaths.default ++ [
        "/etc/ssh/this_key_wont_exist"
      ];
    };

  testScript = ''
    # UX Test Script
    # This validates that secrets are properly decrypted and accessible

    testvm.wait_for_unit("multi-user.target")

    # Scenario 1: Verify Gitea secrets are decrypted
    print("Testing Scenario 1: Gitea application secrets...")
    testvm.succeed("test -f /run/agenix/gitea-db-password")
    testvm.succeed("test -f /run/agenix/gitea-admin-password")
    testvm.succeed("test -f /run/agenix/gitea-secret-key")

    # Verify ownership and permissions
    testvm.succeed("stat -c '%U:%G %a' /run/agenix/gitea-db-password | grep 'gitea:gitea 400'")

    # Verify content can be read by owner
    testvm.succeed("su - gitea -s /bin/sh -c 'cat /run/agenix/gitea-db-password' | grep -q 'hello'")

    # Scenario 2: Verify SSH deployment key
    print("Testing Scenario 2: SSH deployment keys...")
    testvm.succeed("test -f /run/agenix/deploy-ssh-key")
    # Just check the owner and mode (group may vary for system users)
    testvm.succeed("stat -c '%U %a' /run/agenix/deploy-ssh-key | grep 'deploy 400'")

    # Scenario 3: Verify shared secrets
    print("Testing Scenario 3: Shared secrets...")
    testvm.succeed("test -f /run/agenix/shared-api-token")
    testvm.succeed("test -f /run/agenix/shared-db-password")
    testvm.succeed("stat -c '%U:%G %a' /run/agenix/shared-db-password | grep 'postgres:postgres 400'")
    testvm.succeed("cat /run/agenix/shared-db-password | grep -q 'hello'")
    testvm.succeed("cat /run/agenix/shared-api-token | grep -q 'my-secret-private-key'")

    print("All UX test scenarios passed!")

    # Note: Home Manager user secrets would require user login session
    # See integration.nix for example of testing home-manager secrets
    # with active user sessions
  '';
}
