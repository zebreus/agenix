let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  "with-public.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { }:
      {
        secret = "my-secret-value";
        public = "my-public-key-content";
      };
  };
  "string-only.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator = { }: "just-a-secret";
  };
}
