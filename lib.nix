# Helper library for agenix
# This file provides utilities for working with agenix secrets

{
  # Extract the public key from a generator function result
  # 
  # This is useful when you want to use a generated public SSH key
  # in the publicKeys field of another secret.
  #
  # Example usage:
  #   let
  #     agenixLib = import <agenix-lib>;
  #     sshKeyPair = builtins.sshKey {};
  #   in {
  #     "ssh-key.age" = {
  #       publicKeys = [ "age1admin..." ];
  #       generator = {}: sshKeyPair;
  #     };
  #     "authorized-hosts.age" = {
  #       publicKeys = [ "age1admin..." (agenixLib.publicKeyOf sshKeyPair) ];
  #     };
  #   }
  #
  # Args:
  #   generatorResult: The result of calling a generator function (e.g., builtins.sshKey {})
  #
  # Returns:
  #   If generatorResult is an attrset with a 'public' key, returns that value.
  #   If generatorResult is just a string, throws an error (no public key available).
  #   Otherwise throws an error.
  publicKeyOf =
    generatorResult:
    if builtins.isAttrs generatorResult then
      if builtins.hasAttr "public" generatorResult then
        generatorResult.public
      else
        throw "Generator result must have a 'public' attribute. Got: ${builtins.toJSON (builtins.attrNames generatorResult)}"
    else
      throw "Generator result must be an attribute set with 'public' and 'secret' keys. Got: ${builtins.typeOf generatorResult}";

  # Extract the secret from a generator function result
  #
  # This is primarily for internal use but can be helpful if you want to
  # reference the secret value in the generator definition.
  #
  # Args:
  #   generatorResult: The result of calling a generator function
  #
  # Returns:
  #   If generatorResult is an attrset with a 'secret' key, returns that value.
  #   If generatorResult is just a string, returns it.
  #   Otherwise throws an error.
  secretOf =
    generatorResult:
    if builtins.isAttrs generatorResult then
      if builtins.hasAttr "secret" generatorResult then
        generatorResult.secret
      else
        throw "Generator result must have a 'secret' attribute"
    else if builtins.isString generatorResult then
      generatorResult
    else
      throw "Generator result must be a string or an attribute set with 'secret' key. Got: ${builtins.typeOf generatorResult}";
}
