# agenix

* [Introduction](#introduction)
* [Problem and solution](#problem-and-solution)
* [Features](#features)
* Installation
  * [flakes](#install-via-flakes)
  * [niv](#install-via-niv)
  * [fetchTarball](#install-via-fetchtarball)
  * [nix-channel](#install-via-nix-channel)
* [Tutorial](#tutorial)
* [Reference](#reference)
  * [`age` module reference](#age-module-reference)
  * [agenix CLI reference](#agenix-cli-reference)
* [Community and Support](#community-and-support)
* [Threat model/Warnings](#threat-model-warnings)
* [Notices](#notices)
* [Overriding age binary](#overriding-age-binary)
* [Rekeying](#rekeying)
* [Contributing](#contributing)
* [Acknowledgements](#acknowledgements)

# agenix - [age](https://github.com/FiloSottile/age)-encrypted secrets for NixOS {#introduction}

`agenix` is a commandline tool for managing secrets encrypted with your existing SSH keys. This project also includes the NixOS module `age` for adding encrypted secrets into the Nix store and decrypting them.

# Problem and solution {#problem-and-solution}

All files in the Nix store are readable by any system user, so it is not a suitable place for including cleartext secrets. Many existing tools (like NixOps deployment.keys) deploy secrets separately from `nixos-rebuild`, making deployment, caching, and auditing more difficult. Out-of-band secret management is also less reproducible.

`agenix` solves these issues by using your pre-existing SSH key infrastructure and `age` to encrypt secrets into the Nix store. Secrets are decrypted using an SSH host private key during NixOS system activation.

# Features {#features}

* Secrets are encrypted with SSH keys
  * system public keys via `ssh-keyscan`
  * can use public keys available on GitHub for users (for example, https://github.com/ryantm.keys)
* No GPG
* Very little code, so it should be easy for you to audit
* Encrypted secrets are stored in the Nix store, so a separate distribution mechanism is not necessary

# Install via Flakes {#install-via-flakes}

## Install module via Flakes

```nix
{
  inputs.agenix.url = "github:ryantm/agenix";
  # optional, not necessary for the module
  #inputs.agenix.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, agenix }: {
    # change `yourhostname` to your actual hostname
    nixosConfigurations.yourhostname = nixpkgs.lib.nixosSystem {
      # change to your system:
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        agenix.nixosModules.default
      ];
    };
  };
}
```

## Install CLI via Flakes

You don't need to install it,

```ShellSession
nix run github:ryantm/agenix -- --help
```

but, if you want to (change the system based on your system):

```nix
{
  environment.systemPackages = [ agenix.packages.x86_64-linux.default ];
}
```

# Install via [niv](https://github.com/nmattia/niv) {#install-via-niv}

First add it to niv:

```ShellSession
$ niv add ryantm/agenix
```

## Install module via niv

Then add the following to your `configuration.nix` in the `imports` list:

```nix
{
  imports = [ "${(import ./nix/sources.nix).agenix}/modules/age.nix" ];
}
```

## Install CLI via niv

To install the `agenix` binary:

```nix
{
  environment.systemPackages = [ (pkgs.callPackage "${(import ./nix/sources.nix).agenix}/pkgs/agenix.nix" {}) ];
}
```

# Install via fetchTarball {#install-via-fetchtarball}

#### Install module via fetchTarball

Add the following to your configuration.nix:

```nix
{
  imports = [ "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/modules/age.nix" ];
}
```

  or with pinning:

```nix
{
  imports = let
    # replace this with an actual commit id or tag
    commit = "298b235f664f925b433614dc33380f0662adfc3f";
  in [
    "${builtins.fetchTarball {
      url = "https://github.com/ryantm/agenix/archive/${commit}.tar.gz";
      # update hash from nix build output
      sha256 = "";
    }}/modules/age.nix"
  ];
}
```

#### Install CLI via fetchTarball

To install the `agenix` binary:

```nix
{
  environment.systemPackages = [ (pkgs.callPackage "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/pkgs/agenix.nix" {}) ];
}
```

# Install via nix-channel {#install-via-nix-channel}

As root run:

```ShellSession
$ sudo nix-channel --add https://github.com/ryantm/agenix/archive/main.tar.gz agenix
$ sudo nix-channel --update
```

## Install module via nix-channel

Then add the following to your `configuration.nix` in the `imports` list:

```nix
{
  imports = [ <agenix/modules/age.nix> ];
}
```

## Install CLI via nix-channel

To install the `agenix` binary:

```nix
{
  environment.systemPackages = [ (pkgs.callPackage <agenix/pkgs/agenix.nix> {}) ];
}
```

# Tutorial {#tutorial}

1. The system you want to deploy secrets to should already exist and
   have `sshd` running on it so that it has generated SSH host keys in
   `/etc/ssh/`.

2. Make a directory to store secrets and `secrets.nix` file for listing secrets and their public keys (This file is **not** imported into your NixOS configuration. It is only used for the `agenix` CLI.):

   ```ShellSession
   $ mkdir secrets
   $ cd secrets
   $ touch secrets.nix
   ```
3. Add public keys to `secrets.nix` file (hint: use `ssh-keyscan` or GitHub (for example, https://github.com/ryantm.keys)):
   ```nix
   let
     user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
     user2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILI6jSq53F/3hEmSs+oq9L4TwOo1PrDMAgcA1uo1CCV/";
     users = [ user1 user2 ];

     system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
     system2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKzxQgondgEYcLpcPdJLrTdNgZ2gznOHCAxMdaceTUT1";
     systems = [ system1 system2 ];
   in
   {
     "secret1.age".publicKeys = [ user1 system1 ];
     "secret2.age".publicKeys = users ++ systems;
     "armored-secret.age" = {
       publicKeys = [ user1 ];
       armor = true;
     };
   }
   ```
4. Edit secret files (these instructions assume your SSH private key is in ~/.ssh/):
   ```ShellSession
   $ agenix edit secret1.age
   ```
5. Add secret to a NixOS module config:
   ```nix
   {
     age.secrets.secret1.file = ../secrets/secret1.age;
   }
   ```
6. Use the secret in your config:
   ```nix
   {
     users.users.user1 = {
       isNormalUser = true;
       hashedPasswordFile = config.age.secrets.secret1.path;
     };
   }
   ```
7. NixOS rebuild or use your deployment tool like usual.

   The secret will be decrypted to the value of `config.age.secrets.secret1.path` (`/run/agenix/secret1` by default).

# Reference {#reference}

## `age` module reference {#age-module-reference}

### `age.secrets`

`age.secrets` attrset of secrets. You always need to use this
configuration option. Defaults to `{}`.

### `age.secrets.<name>.file`

`age.secrets.<name>.file` is the path to the encrypted `.age` for this
secret. This is the only required secret option.

Example:

```nix
{
  age.secrets.monitrc.file = ../secrets/monitrc.age;
}
```

### `age.secrets.<name>.path`

`age.secrets.<name>.path` is the path where the secret is decrypted
to. Defaults to `/run/agenix/<name>` (`config.age.secretsDir/<name>`).

Example defining a different path:

```nix
{
  age.secrets.monitrc = {
    file = ../secrets/monitrc.age;
    path = "/etc/monitrc";
  };
}
```

For many services, you do not need to set this. Instead, refer to the
decryption path in your configuration with
`config.age.secrets.<name>.path`.

Example referring to path:

```nix
{
  users.users.ryantm = {
    isNormalUser = true;
    hashedPasswordFile = config.age.secrets.passwordfile-ryantm.path;
  };
}
```

#### builtins.readFile anti-pattern

```nix
{
  # Do not do this!
  config.password = builtins.readFile config.age.secrets.secret1.path;
}
```

This can cause the cleartext to be placed into the world-readable Nix
store. Instead, have your services read the cleartext path at runtime.

### `age.secrets.<name>.mode`

`age.secrets.<name>.mode` is permissions mode of the decrypted secret
in a format understood by chmod. Usually, you only need to use this in
combination with `age.secrets.<name>.owner` and
`age.secrets.<name>.group`

Example:

```nix
{
  age.secrets.nginx-htpasswd = {
    file = ../secrets/nginx.htpasswd.age;
    mode = "770";
    owner = "nginx";
    group = "nginx";
  };
}
```

### `age.secrets.<name>.owner`

`age.secrets.<name>.owner` is the username of the decrypted file's
owner. Usually, you only need to use this in combination with
`age.secrets.<name>.mode` and `age.secrets.<name>.group`

Example:

```nix
{
  age.secrets.nginx-htpasswd = {
    file = ../secrets/nginx.htpasswd.age;
    mode = "770";
    owner = "nginx";
    group = "nginx";
  };
}
```

### `age.secrets.<name>.group`

`age.secrets.<name>.group` is the name of the decrypted file's
group. Usually, you only need to use this in combination with
`age.secrets.<name>.owner` and `age.secrets.<name>.mode`

Example:

```nix
{
  age.secrets.nginx-htpasswd = {
    file = ../secrets/nginx.htpasswd.age;
    mode = "770";
    owner = "nginx";
    group = "nginx";
  };
}
```

### `age.secrets.<name>.symlink`

`age.secrets.<name>.symlink` is a boolean. If true (the default),
secrets are symlinked to `age.secrets.<name>.path`. If false, secrets
are copied to `age.secrets.<name>.path`. Usually, you want to keep
this as true, because it secure cleanup of secrets no longer
used. (The symlink will still be there, but it will be broken.) If
false, you are responsible for cleaning up your own secrets after you
stop using them.

Some programs do not like following symlinks (for example Java
programs like Elasticsearch).

Example:

```nix
{
  age.secrets."elasticsearch.conf" = {
    file = ../secrets/elasticsearch.conf.age;
    symlink = false;
  };
}
```

### `age.secrets.<name>.name`

`age.secrets.<name>.name` is the string of the name of the file after
it is decrypted. Defaults to the `<name>` in the attrpath, but can be
set separately if you want the file name to be different from the
attribute name part.

Example of a secret with a name different from its attrpath:

```nix
{
  age.secrets.monit = {
    name = "monitrc";
    file = ../secrets/monitrc.age;
  };
}
```

### `age.ageBin`

`age.ageBin` the string of the path to the `age` binary. Usually, you
don't need to change this. Defaults to `age/bin/age`.

Overriding `age.ageBin` example:

```nix
{pkgs, ...}:{
    age.ageBin = "${pkgs.age}/bin/age";
}
```

### `age.identityPaths`

`age.identityPaths` is a list of paths to recipient keys to try to use to
decrypt the secrets. By default, it is the `rsa` and `ed25519` keys in
`config.services.openssh.hostKeys`, and on NixOS you usually don't need to
change this. The list items should be strings (`"/path/to/id_rsa"`), not
nix paths (`../path/to/id_rsa`), as the latter would copy your private key to
the nix store, which is the exact situation `agenix` is designed to avoid. At
least one of the file paths must be present at runtime and able to decrypt the
secret in question. Overriding `age.identityPaths` example:

```nix
{
    age.identityPaths = [ "/var/lib/persistent/ssh_host_ed25519_key" ];
}
```

### `age.secretsDir`

`age.secretsDir` is the directory where secrets are symlinked to by
default. Usually, you don't need to change this. Defaults to
`/run/agenix`.

Overriding `age.secretsDir` example:

```nix
{
    age.secretsDir = "/run/keys";
}
```

### `age.secretsMountPoint`

`age.secretsMountPoint` is the directory where the secret generations
are created before they are symlinked. Usually, you don't need to
change this. Defaults to `/run/agenix.d`.


Overriding `age.secretsMountPoint` example:

```nix
{
    age.secretsMountPoint = "/run/secret-generations";
}
```

## agenix CLI reference {#agenix-cli-reference}

```
agenix - edit and rekey age secret files

USAGE:
    agenix [OPTIONS] <COMMAND>

COMMANDS:
    edit      Edit a secret file using $EDITOR (alias: e)
    decrypt   Decrypt a secret file to stdout or a file (alias: d)
    rekey     Re-encrypt all secrets with updated recipients (alias: r)
    generate  Generate secrets using generator functions from rules (alias: g)

GLOBAL OPTIONS:
    -r, --rules <FILE>          Path to Nix rules file (default: ./secrets.nix)
    -i, --identity <KEY>        Identity (private key) to use when decrypting.
                                Can be specified multiple times. Identities are
                                tried in order: explicitly specified first, then
                                default system identities.
        --no-system-identities  Do not use default system identities
                                (~/.ssh/id_rsa, ~/.ssh/id_ed25519)
    -v, --verbose               Verbose output
    -h, --help                  Print help
    -V, --version               Print version

EDIT OPTIONS:
    -e, --editor <COMMAND>   Editor to use (default: $EDITOR or vi)

DECRYPT OPTIONS:
    -o, --output <FILE>    Output file (defaults to stdout)

GENERATE OPTIONS:
    -f, --force     Overwrite existing secret files
    -n, --dry-run   Show what would be generated without making changes

EXAMPLES:
    agenix edit secret.age
    agenix -i ~/.ssh/id_ed25519 decrypt secret.age -o plaintext.txt
    agenix -i key1 -i key2 --no-system-identities decrypt secret.age
    agenix rekey
    agenix generate --dry-run

ENVIRONMENT VARIABLES:
    EDITOR   Editor to use when editing secrets (default: vi)
    RULES    Path to Nix file specifying recipient public keys (default: ./secrets.nix)

If STDIN is not interactive, EDITOR will be set to "cp /dev/stdin"
```

For the full CLI reference including generator functions, automatic generator selection, and advanced features, see the [agenix CLI documentation](../pkgs/README.md).

# Community and Support {#community-and-support}

Support and development discussion is available here on GitHub and
also through [Matrix](https://matrix.to/#/#agenix:nixos.org).

# Threat model/Warnings {#threat-model-warnings}

This project has not been audited by a security professional.

People unfamiliar with `age` might be surprised that secrets are not
authenticated. This means that every attacker that has write access to
the secret files can modify secrets because public keys are exposed.
This seems like not a problem on the first glance because changing the
configuration itself could expose secrets easily. However, reviewing
configuration changes is easier than reviewing random secrets (for
example, 4096-bit rsa keys). This would be solved by having a message
authentication code (MAC) like other implementations like GPG or
[sops](https://github.com/Mic92/sops-nix) have, however this was left
out for simplicity in `age`.

# Notices {#notices}

* Password-protected ssh keys: since age does not support ssh-agent, password-protected ssh keys do not work well. For example, if you need to rekey 20 secrets you will have to enter your password 20 times.

# Overriding age binary {#overriding-age-binary}

The agenix CLI uses `age` by default as its age implemenation, you
can use the `rage` implementation with Flakes like this:

```nix
{
  pkgs,
  lib,
  agenix,
  ...
}:
{
  environment.systemPackages = [
    (agenix.packages.x86_64-linux.default.override { ageBin = lib.getExe pkgs.rage; })
  ];
}
```

Please note that the behavior of alternative implementations may not match that required for agenix to function, and the agenix team does not plan to provide support for bugs encountered when using agenix with nondefault implementations.

# Rekeying {#rekeying}

If you change the public keys in `secrets.nix`, you should rekey your
secrets:

```ShellSession
$ agenix --rekey
```

To rekey a secret, you have to be able to decrypt it. Because of
randomness in `age`'s encryption algorithms, the files always change
when rekeyed, even if the identities do not. (This eventually could be
improved upon by reading the identities from the age file.)

# Contributing {#contributing}

* The main branch is protected against direct pushes
* All changes must go through GitHub PR review and get at least one approval
* PR titles and commit messages should be prefixed with at least one of these categories:
  * contrib - things that make the project development better
  * doc - documentation
  * feature - new features
  * fix - bug fixes
* Please update or make integration tests for new features
* Use `nix fmt` to format nix code


## Tests

You can run the tests with

```ShellSession
nix flake check
```

You can run the integration tests in interactive mode like this:

```ShellSession
nix run .#checks.x86_64-linux.integration.driverInteractive
```

After it starts, enter `run_tests()` to run the tests.

# Acknowledgements {#acknowledgements}

This project is based off of [sops-nix](https://github.com/Mic92/sops-nix) created Mic92. Thank you to Mic92 for inspiration and advice.
