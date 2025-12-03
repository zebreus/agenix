let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  # Generate an SSH key for deployment
  "deploy-key" = {
    publicKeys = [
      user1
      system1
    ];
    generator = builtins.sshKey;
  };

  # Use the deploy key's public key in another secret's publicKeys
  "authorized-keys" = {
    publicKeys = [
      user1
      system1
      "deploy-key" # This references the public key from deploy-key.pub
    ];
  };

  # Can also reference secret names directly
  "backup-config" = {
    publicKeys = [
      user1
      "deploy-key" # References the secret name
    ];
  };

  # NEW: Use dependencies to reference public content in generators
  "ssh-config" = {
    publicKeys = [
      user1
      system1
    ];
    dependencies = [ "deploy-key" ];
    generator =
      { publics }:
      # Access the deploy key's public key in the generator
      ''
        Host myserver
          HostName myserver.example.com
          User deploy
          IdentityFile /etc/ssh/deploy_key
          # Public key: ${publics."deploy-key"}
      '';
  };
}
