let
  # Import the agenix library for helper functions
  agenixLib = import ../../lib.nix;

  # Define some admin keys that can decrypt all secrets
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";

  # Generate an SSH keypair - this will be evaluated once and reused
  sshKeyPair = builtins.sshKey { };

  # Generate another SSH keypair for a different service
  serviceKeyPair = builtins.sshKey { };
in
{
  # Generate and store the SSH private key
  "ssh-deploy-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { }:
      {
        secret = sshKeyPair.private;
        public = sshKeyPair.public;
      };
  };

  # Use the public key from the generated SSH key in another secret
  # This demonstrates the ergonomic way to reference generated public keys
  "authorized-keys.age" = {
    publicKeys = [
      user1
      system1
      (agenixLib.publicKeyOf sshKeyPair)
    ];
    generator = { }: "Some authorized keys content";
  };

  # Another example: generate a service key and use it
  "service-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { }:
      {
        secret = serviceKeyPair.private;
        public = serviceKeyPair.public;
      };
  };

  # Use the service public key in a configuration secret
  "service-config.age" = {
    publicKeys = [
      user1
      system1
      (agenixLib.publicKeyOf serviceKeyPair)
    ];
    generator = { }: "service_ssh_key=${agenixLib.publicKeyOf serviceKeyPair}";
  };

  # Traditional secret without generator
  "password.age" = {
    publicKeys = [
      user1
      system1
    ];
  };

  # Mix of generated and static public keys
  "mixed-secret.age" = {
    publicKeys = [
      user1
      system1
      (agenixLib.publicKeyOf sshKeyPair)
      (agenixLib.publicKeyOf serviceKeyPair)
    ];
    generator = { }: builtins.randomString 32;
  };
}
