# Test that the old nested public API (age.secrets.<name>.public) no longer works
# This test should FAIL to evaluate, proving the old API is removed
{
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
}:
let
  # This should fail to evaluate because 'public' is no longer a valid option under secrets
  testConfig = pkgs.nixos {
    imports = [
      ../modules/age.nix
    ];

    age.secrets.test-secret = {
      file = ./example/secret-with-public.age;
      # This should cause an evaluation error since 'public' is not a valid option anymore
      public.file = ./example/secret-with-public.pub;
      public.installPath = "/etc/test.pub";
    };
  };
in
{
  # If this evaluates without error, the old API is still present (test fails)
  # If this fails to evaluate with an error about unknown option 'public', test passes
  inherit testConfig;
}
