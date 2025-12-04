# Usability Testing - Key Issues Summary

This is a quick reference summary of the usability issues found during comprehensive testing. See `USABILITY_TESTING_REPORT.md` for full details.

## 🔴 Critical - Fix Before Stable Release

### Issue #7: Decrypt Silently Overwrites Files
**Risk**: Data Loss
```bash
$ echo "important" > file.txt
$ agenix decrypt secret -o file.txt  # Overwrites without warning!
```
**Fix**: Require `--force` flag or warn before overwriting

## 🟡 High Priority - Should Fix Soon

### Issue #1: Default Identities Not Used Consistently
**Problem**: `list --status` doesn't use `~/.ssh/id_*` keys without explicit `-i`
```bash
$ agenix list --status          # Shows NO_DECRYPT
$ agenix -i ~/.ssh/id_ed25519 list --status  # Shows EXISTS
```
**Fix**: Use default SSH keys unless `--no-system-identities` is specified

### Issue #2: Cryptic Nix Errors for Undefined Secrets
**Problem**: Raw Nix evaluation errors instead of user-friendly messages
```bash
$ echo "test" | agenix encrypt undefined-secret
error[E005]: attribute with name 'undefined-secret' could not be found in the set
```
**Fix**: Parse and show: "Error: Secret 'undefined-secret' is not defined in secrets.nix"

### Issue #6: Generate Inconsistently Handles Overwrites
**Problem**: `encrypt` requires `--force` to overwrite, but `generate` doesn't
```bash
$ echo "new" | agenix encrypt secret  # Error: use --force
$ agenix generate secret               # Silently overwrites
```
**Fix**: Make both commands require `--force` for consistency

## 🟢 Medium Priority - Nice to Have

### Issue #4: Confusing Public File Save Message
```bash
$ agenix edit --public deploy-key
Saving to: deploy-key  # Should say deploy-key.pub
```

### Issue #9: List Silently Ignores Non-existent Secrets
```bash
$ agenix list secret1 typo-secret secret2
secret1
secret2
# No warning about typo-secret
```

## 🔵 Low Priority - Future Enhancements

- **Issue #5**: Could auto-strip `.age` extension (currently shows good error)
- **Issue #3**: Edit command stdin handling unclear (may be intentional)
- **Issue #8**: Cryptic errors for undefined secrets in edit (duplicate of #2)

## Test Coverage

- ✅ 8/8 commands tested (100%)
- ✅ 7/7 global options tested (100%)
- ✅ 15+ error scenarios tested
- ✅ 10+ edge cases tested

## Overall Assessment

**Score**: 7.5/10

**Strengths**:
- Excellent error messages with hints
- Automatic dependency management
- Comprehensive help documentation
- Good dry-run support

**Needs Work**:
- Critical data loss risk in decrypt
- Inconsistent behavior across commands
- Some error messages need improvement

**Recommendation**: Production-ready for experienced users. Address critical and high-priority issues before wider adoption.
