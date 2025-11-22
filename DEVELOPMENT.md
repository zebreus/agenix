# Development Guide

This guide provides information for developers and automated tools (like GitHub Copilot) working on the agenix project.

## Code Formatting

### Nix Files

All Nix files must be formatted using `nix fmt` before committing.

**Format all Nix files:**
```bash
nix fmt
```

**Check formatting (CI mode):**
```bash
nix fmt . -- --ci
```

The formatter is configured in `flake.nix` and uses `nixfmt-tree` (RFC-style formatter).

## Testing

Run the full test suite:
```bash
nix flake check
```

Run specific checks:
```bash
# Build the package
nix build

# Build documentation
nix build .#doc
```

## Development Workflow

1. Make your changes
2. Format code: `nix fmt`
3. Run tests: `nix flake check`
4. Commit and push

## Contributing

See the [Contributing section](README.md#contributing) in README.md for PR guidelines and conventions.
