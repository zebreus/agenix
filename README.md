# agenix

[age](https://github.com/FiloSottile/age)-encrypted secrets for NixOS.

> **⚠️ Experimental:** This project is experimental. The primary goal is to explore the current state of AI-assisted coding (and to see if [snix](https://github.com/snix-nix/snix) is ready), not to provide stable software. Use at your own risk.

## Features

- **SSH-based encryption** – Use existing SSH keys (system or user) to encrypt secrets
- **Nix store integration** – Encrypted secrets deploy with `nixos-rebuild`
- **Automatic decryption** – Secrets are decrypted to `/run/agenix/` at system activation
- **Maximalist** – Prioritizes user-friendliness and features over minimalism

## Quick Example

**1. Define recipients** (`secrets/secrets.nix`):

```nix
let
  user = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."; # ~/.ssh/id_ed25519.pub
  host = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."; # ssh-keyscan hostname
in {
  "db-password.age".publicKeys = [ user host ];
}
```

**2. Create the secret**:

```ShellSession
$ cd secrets && agenix edit db-password.age
```

**3. Use in NixOS configuration**:

```nix
{
  age.secrets.db-password.file = ./secrets/db-password.age;
  
  services.grafana.database.passwordFile = config.age.secrets.db-password.path;
}
```

## Installation (Flakes)

```nix
{
  inputs.agenix.url = "github:ryantm/agenix";

  outputs = { nixpkgs, agenix, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        agenix.nixosModules.default
        { environment.systemPackages = [ agenix.packages.x86_64-linux.default ]; }
      ];
    };
  };
}
```

<details>
<summary>Other installation methods (niv, nix-channel, fetchTarball)</summary>

### niv

```ShellSession
$ niv add ryantm/agenix
```

```nix
{
  imports = [ "${(import ./nix/sources.nix).agenix}/modules/age.nix" ];
  environment.systemPackages = [ (pkgs.callPackage "${(import ./nix/sources.nix).agenix}/pkgs/agenix.nix" {}) ];
}
```

### nix-channel

```ShellSession
$ sudo nix-channel --add https://github.com/ryantm/agenix/archive/main.tar.gz agenix
$ sudo nix-channel --update
```

```nix
{
  imports = [ <agenix/modules/age.nix> ];
  environment.systemPackages = [ (pkgs.callPackage <agenix/pkgs/agenix.nix> {}) ];
}
```

### fetchTarball

```nix
{
  imports = [ "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/modules/age.nix" ];
}
```

</details>

## CLI Commands

```ShellSession
$ agenix edit secret.age                    # Create/edit a secret
$ echo "val" | agenix encrypt secret.age    # Encrypt from stdin
$ agenix decrypt secret.age                 # Decrypt to stdout
$ agenix rekey                              # Re-encrypt with updated keys
```

## Documentation

- **[Tutorial](doc/toc.md#tutorial)** – Step-by-step guide
- **[Module Reference](doc/toc.md#reference)** – All `age.secrets.*` options
- **[CLI Reference](pkgs/README.md)** – Full CLI documentation
- **[Threat Model](doc/toc.md#threat-model-warnings)** – Security considerations

## Home Manager

For user-scoped secrets, use `agenix.homeManagerModules.default`. See the [tutorial](doc/toc.md#tutorial) for details.

## Contributing

See [CONTRIBUTING](doc/toc.md#contributing). Run tests with `nix flake check`.

## Acknowledgements

Based on [sops-nix](https://github.com/Mic92/sops-nix) by Mic92.

## Related Projects

- **[ryantm/agenix](https://github.com/ryantm/agenix)** – The original agenix project. Provides a minimal, easy-to-audit implementation. If you prefer stability and simplicity over features, use that instead.

## AI Disclosure

This repository was largely slop-coded with GitHub Copilot. The Rust port was initially drafted by Copilot, then manually cleaned up. Many tests were AI-generated, and most subsequent changes were made via Copilot-assisted PRs. For full transparency, see the [pull request history](https://github.com/zebreus/agenix/pulls?q=is%3Apr).
