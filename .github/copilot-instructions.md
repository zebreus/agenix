# Copilot Instructions

## Formatting

Format Nix files before committing:
```bash
nix fmt
```

Check formatting (CI):
```bash
nix fmt . -- --ci
```

## Rust (pkgs directory)

Before committing changes to Rust code in the `pkgs` directory:

Format Rust code:
```bash
cd pkgs && cargo fmt
```

Run tests:
```bash
cd pkgs && cargo test
```

## Testing

Run the full test suite after all other checks pass (this takes ~2 minutes):
```bash
nix flake check
```

## Documentation

After `nix flake check` passes, update/adjust the following documentation if CLI changes were made:
- Main readme (`readme.adoc`)
- CLI manpage (`pkgs/readme.adoc`)
- Clap help messages (in `pkgs/src/cli.rs`)
- Modules readme (`modules/readme.adoc`)
