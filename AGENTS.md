# Repository Guidelines

## Project Overview

CypherStorm is a Go application for protecting and restoring files/directories, structured hashing, deterministic compression/encryption benchmarks, and interactive terminal workflows. Protection is a reversible tar, compression, and authenticated v1 encryption pipeline. CLI and TUI adapters share one UI-neutral application service.

## Architecture

```text
cmd/cypherstorm/main.go
  -> internal/ui/cli
  -> internal/ui/tui
       both -> internal/app
                 -> archive + compress + crypto + format + fsutil + hashing + kdf + report
```

Dependency rules:

- `main` is the only `os.Exit` boundary.
- CLI and TUI do not import each other.
- UI adapters do not implement archive/compression/crypto orchestration.
- `internal/app` does not print or read terminal state.
- Capability packages do not import UI packages.
- Restore reads authenticated cipher/codec/KDF metadata; adapters never ask users to choose it.
- Do not recreate the deleted legacy `internal/pipeline`, `internal/encryption`, `internal/keyman`, `internal/archiver`, `internal/compression`, `constants`, or `utils` packages.

## Key Directories

- `cmd/cypherstorm/` — executable and sole process-exit boundary.
- `internal/app/` — request/result APIs, progress events, transactional orchestration.
- `internal/ui/cli/` — Cobra constructors, secure credential input, rendering.
- `internal/ui/tui/` — Bubble Tea state machine, forms, asynchronous commands, cancellation.
- `internal/archive/` — safe tar creation and bounded extraction.
- `internal/compress/` — streaming codecs and deterministic registry.
- `internal/crypto/` — authenticated v1 record engine and cipher suites.
- `internal/format/` — wire IDs, header/record framing, allocation bounds.
- `internal/fsutil/` — private workspaces and atomic no-replace publication.
- `internal/hashing/` — context-aware digest operations.
- `internal/kdf/` — typed credential derivation and bounded Argon2 policy.
- `internal/report/` — benchmark models plus text/XLSX renderers.

## Development Commands

Use the checked-in Makefile:

```sh
make build       # go build -o cypherstorm ./cmd/cypherstorm
make run         # go run ./cmd/cypherstorm
make test        # go test ./...
make key-gen     # openssl rand -out key.bin 32; chmod 600
make clean       # remove ./cypherstorm
```

Use Go 1.23.2 or a compatible toolchain. Use Go modules only. Do not commit binaries, keys, benchmark reports, coverage output, or local environment files.

## Code Conventions

- Prefer simple concrete services and narrow consumer-owned interfaces in adapters/tests.
- Preserve streaming `io.Reader`/`io.Writer` transforms; do not read whole protected payloads into memory.
- Use typed algorithm IDs and deterministic registries. Never use map iteration for user-visible ordering.
- Return contextual `%w` errors. Do not call `log.Fatal` or `os.Exit` below `main`.
- Explicitly observe close, synchronization, and compressor/workbook finalization errors.
- Every operation accepts `context.Context`; cancellation must remove staging and publish nothing partial.
- Business logic returns structured values and typed events. UI adapters alone render output.
- Password/raw-key bytes must never be formatted, logged, rendered, or placed in command-line arguments.

## Security and Compatibility Boundaries

- `FORMAT.md` is the v1 on-disk contract. Change encrypt/decrypt and compatibility tests together.
- Legacy protected formats are unsafe and unsupported. Never add a fallback decoder.
- Validate serialized Argon2 parameters before invoking Argon2.
- Keep protect/restore credential semantics aligned across `app`, `crypto`, `format`, and `kdf`.
- Final protected output uses same-directory atomic publication. No-overwrite must be enforced by an OS no-replace primitive, not a check-then-rename.
- Restore uses an inaccessible fresh staging directory and publishes only after final authentication, decompression, extraction, limits, and metadata succeed.
- Archive extraction is security-sensitive: reject platform-ambiguous paths, traversal, escaping symlinks, unsupported nodes, and resource-limit violations.
- Raw-key files are exactly 32 binary bytes, regular, non-symlink, and `0600` or stricter on Unix.

## Testing and QA

Native colocated Go tests are required for behavior changes. Prioritize observable contracts:

- password and raw-key protect/restore round trips;
- both ciphers and all codecs across boundaries;
- tamper, truncation, reorder, duplication, trailing-data, and hostile-resource failures;
- existing-output preservation and failed-restore nonpublication;
- cancellation at every stage and concurrent workspace isolation;
- archive traversal, Windows-ambiguous paths, symlinks, limits, and metadata;
- CLI secret input and end-to-end commands;
- deterministic TUI state transitions, masking, stale-message rejection, resize, and cancellation;
- pseudo-terminal interactive/noninteractive routing and terminal restoration.

Run focused package tests while developing, then `go test ./...`. Run `govulncheck ./...` after dependency changes and resolve every reachable finding before release.
