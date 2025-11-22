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

## Testing

```bash
nix flake check
```
