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

      # Configure agenix with secrets path
      age.secretsPath = ./.; # Points to test/ux-testing directory

      # Scenario 1: Self-hosted Gitea with database secrets
      # This tests a common use case: web application with database
      age.secrets.gitea-db-password = {
        owner = "gitea";
        mode = "0400";
      };

      age.secrets.gitea-admin-password = {
        owner = "gitea";
        mode = "0400";
      };

      age.secrets.gitea-secret-key = {
        owner = "gitea";
        mode = "0400";
      };

      # Set up Gitea service (simplified for testing)
      users.users.gitea = {
        isSystemUser = true;
        group = "gitea";
        uid = 1001;
      };
      users.groups.gitea.gid = 1001;

      # Scenario 2: SSH deployment key management
      # This tests managing SSH keys for deployment
      age.secrets.deploy-ssh-key = {
        path = "/var/lib/deploy/.ssh/id_ed25519";
        owner = "deploy";
        mode = "0400";
      };

      users.users.deploy = {
        isSystemUser = true;
        group = "deploy";
        uid = 1002;
      };
      users.groups.deploy.gid = 1002;

      # Scenario 3: Multi-service secret sharing
      # Tests shared secrets with proper permissions
      age.secrets.shared-api-token = {
        owner = "root";
        mode = "0440";
      };

      age.secrets.shared-db-password = {
        owner = "postgres";
        group = "postgres";
        mode = "0400";
      };

      users.users.postgres = {
        isSystemUser = true;
        group = "postgres";
        uid = 1003;
      };
      users.groups.postgres.gid = 1003;

      # Scenario 4: Home Manager user secrets
      users = {
        mutableUsers = false;
        users.testuser = {
          isNormalUser = true;
          uid = 1000;
          initialPassword = "test";
        };
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
              file = ./user-github-token.age;
              mode = "0600";
            };

            secrets.user-ssh-key = {
              file = ./user-ssh-key.age;
              path = "/home/testuser/.ssh/deploy_key";
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
    testvm.succeed("su - gitea -c 'cat /run/agenix/gitea-db-password' | grep -q 'gitea_db_secret_password_12345'")

    # Scenario 2: Verify SSH deployment key
    print("Testing Scenario 2: SSH deployment keys...")
    testvm.succeed("test -f /var/lib/deploy/.ssh/id_ed25519")
    testvm.succeed("stat -c '%U:%G %a' /var/lib/deploy/.ssh/id_ed25519 | grep 'deploy:deploy 400'")

    # Scenario 3: Verify shared secrets
    print("Testing Scenario 3: Shared secrets...")
    testvm.succeed("test -f /run/agenix/shared-api-token")
    testvm.succeed("test -f /run/agenix/shared-db-password")
    testvm.succeed("stat -c '%U:%G %a' /run/agenix/shared-db-password | grep 'postgres:postgres 400'")

    # Scenario 4: Verify home-manager user secrets
    print("Testing Scenario 4: Home Manager user secrets...")
    testvm.wait_for_unit("home-manager-testuser.service")
    testvm.succeed("test -f /run/user/1000/agenix/user-github-token")
    testvm.succeed("test -f /home/testuser/.ssh/deploy_key")

    # Verify user can read their own secrets
    testvm.succeed("su - testuser -c 'cat /run/user/1000/agenix/user-github-token' | grep -q 'ghp_github_token_example'")

    # UX Observation: Test secret regeneration/updates
    print("Testing secret lifecycle management...")
    testvm.succeed("test -d /run/agenix.d")

    # Verify symlinks work correctly
    testvm.succeed("readlink /run/agenix/gitea-db-password")

    print("All UX test scenarios passed!")
  '';
}
