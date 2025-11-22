let
  # Define some admin keys that can decrypt all secrets
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  # Generate and store an SSH private key
  "ssh-deploy-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { }:
      let
        keypair = builtins.sshKey { };
      in
      {
        secret = keypair.private;
        public = keypair.public;
      };
  };

  # Use the public key from ssh-deploy-key.age by referencing its name
  "authorized-keys.age" = {
    publicKeys = [
      user1
      system1
      "ssh-deploy-key.age" # This will automatically resolve to the public key
    ];
    generator = { }: "Some authorized keys content";
  };

  # Another secret also using the same SSH key
  "server-config.age" = {
    publicKeys = [
      user1
      "ssh-deploy-key.age" # Can be reused multiple times
    ];
    generator =
      { }:
      let
        sshKey = builtins.sshKey { };
      in
      "server_config_data";
  };

  # A secret that doesn't use any references
  "regular-secret.age" = {
    publicKeys = [
      user1
      system1
    ];
  };
}
