# Core design: the secret resolution engine

The core of agenix is a single lazy resolution engine (`Engine` in
`pkgs/src/nix/engine.rs`). Every command is a thin wrapper:
initialize the engine, ask it for things, format the output. The engine
is the only component that reads or writes secret files.

## Architecture

- **One engine, all commands.** `generate`, `check`, `list`, `edit`,
  `encrypt`, `decrypt`, and `rekey` all go through the engine. Commands
  never touch `.age`/`.pub` files directly.
- **Dependencies via Nix laziness.** Generators receive lazy
  `builtins.getSecret` / `builtins.getPublic` thunks for every entry in
  secrets.nix. Forcing a thunk re-enters the engine, which loads,
  decrypts, or generates the referenced entry on demand. There is no
  hand-rolled dependency ordering.
- **Per-entry state machine.** Each entry has two parts (secret and
  public), each in one of these states:

  | State            | Meaning                                              |
  |------------------|------------------------------------------------------|
  | `Unknown`        | Not resolved yet                                     |
  | `Encrypted`      | Loaded from disk, still ciphertext                   |
  | `PlainText`      | Available in plaintext (decrypted or public content) |
  | `NewlyGenerated` | Produced this run, not yet persisted                 |
  | `WorkInProgress` | Currently being generated — hitting this is a cycle  |
  | `Missing`        | Expected but not on disk and not generatable         |
  | `NotNeeded`      | Entry declares this part does not exist              |

- **One eval per entry config.** `RawSecretEntry` fetches an entry's
  `publicKeys`, `armor`, `hasSecret`/`hasPublic`, `dependencies`, and
  generator presence in a single `deepSeq`'d Nix evaluation.
- **Single-threaded.** The builtins re-enter the engine in the middle of
  an evaluation the engine itself started. The engine assumes one
  thread; no `Mutex`/`parking_lot` gymnastics.

## Settled decisions

1. **getSecret returns plaintext, decrypted lazily.** Decryption
   identities are part of the engine's configuration. If a forced thunk
   needs an existing encrypted secret that cannot be decrypted and does
   not qualify for regeneration, the error must be helpful and carry the
   full "needed by" chain, e.g.: cannot decrypt `B` (no matching
   identity) → needed by generator of `A` → provide an identity or allow
   regeneration. The re-entrant call chain plus `rootcause` context
   nesting produces this trail naturally.

2. **Transactional flush.** The engine resolves everything in memory
   first. Only a fully successful resolution reaches disk: all writes
   are staged as temp files in the secrets directory and renamed into
   place only after every write succeeded. Partial results never land
   on disk. Dry-run = resolve, report, skip the flush.

3. **hasSecret/hasPublic defaulting.** Inferring the output shape of an
   explicit generator would require running it (probing), which is
   impossible when its dependencies cannot be decrypted — so we do not
   infer. Rules:
   - No generator, no declarations: `hasSecret = true, hasPublic = false`.
     Exception: `{ hasSecret = false; }` implies `hasPublic = true`.
   - Name-based implicit generators (`*_ed25519`, `*_wg`, `*password`, …)
     carry their known shape.
   - Explicit generator: same default (`hasSecret = true, hasPublic =
     false`) unless declared otherwise (or the name implies otherwise).
   - At generation time the engine validates the generator's actual
     output against the effective declaration and errors on mismatch.
   - `check` errors when files on disk contradict the effective
     declaration.

4. **`dependencies` is cascade-only metadata.** Never used for ordering
   or reading (laziness handles that). Only used for invalidation:
   regenerating `A` also regenerates entries that declare `A` as a
   dependency, unless `--no-dependencies` is given.

5. **CLI → EntryMode mapping.** Modes are per entry, assigned at init:

   | Invocation                          | Targets         | Everything else    |
   |-------------------------------------|-----------------|--------------------|
   | `generate`                          | —               | `GenerateIfMissing`|
   | `generate --force`                  | —               | `ForceGenerate`    |
   | `generate S…`                       | `Generate`      | `GenerateIfMissing`|
   | `generate S… --force`               | `ForceGenerate` | `GenerateIfMissing`|
   | `generate S… --no-dependencies`     | `Generate`      | `ReadOnly`         |
   | read-only commands (`list`, `check`)| —               | `ReadOnly`         |

   Non-target entries with `GenerateIfMissing` are only reachable
   through a forced dependency thunk, so unrelated secrets are never
   created as a side effect. The reverse cascade (decision 4) adds the
   dependents of regenerated targets to the target set.

6. **Errors accumulate.** `check` (and generally any command that can
   report more than one problem) collects diagnostics in a
   `ReportCollection` instead of failing on the first. Error handling is
   `rootcause` throughout; no `anyhow` in the new core.

7. **Secret names are strict.** Names must not contain `/`, must not
   start with `.`, and must not end in `.age` — the `.age` suffix gets a
   "did you mean" error instead of silent stripping. No backwards
   compatibility with the old suffixed form.

## Generator calling convention

Generators are called callPackage-style: the argument attrset
(`{ secrets, publics }`, all values lazy thunks) is intersected with
`builtins.functionArgs` of the generator, so a generator receives exactly
the arguments its pattern names. `{ }:` receives nothing, `{ publics }:`
receives only `publics`, plain lambdas (`_:`) receive `{ }`. Non-function
generators are constant values. Bare builtins
(`generator = builtins.sshKey`) are not supported — `functionArgs` cannot
introspect them; wrap them: `generator = { }: builtins.sshKey { };`.

## Non-goals

- No speculative caching layers (`cached`, `cachelito-core`,
  `once_cell` are not dependencies). `load_entry`'s hand-rolled
  memoization covers the one hot path.
- No static analysis of generator functions to infer output shape.
- No multi-threading in the engine.
