let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  # Generate an SSH key for deployment
  "deploy-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator = builtins.sshKey;
  };

  # Use the deploy key's public key in another secret's publicKeys
  "authorized-keys.age" = {
    publicKeys = [
      user1
      system1
      "deploy-key" # This references the public key from deploy-key.age.pub
    ];
  };

  # Also works with .age suffix
  "backup-config.age" = {
    publicKeys = [
      user1
      "deploy-key.age" # Can also reference with .age suffix
    ];
  };

  # NEW: Use dependencies to reference public content in generators
  "ssh-config.age" = {
    publicKeys = [
      user1
      system1
    ];
    dependencies = [ "deploy-key" ];
    generator =
      { secrets }:
      # Access the deploy key's public key in the generator
      ''
        Host myserver
          HostName myserver.example.com
          User deploy
          IdentityFile /etc/ssh/deploy_key
          # Public key: ${secrets."deploy-key".public}
      '';
  };
}
