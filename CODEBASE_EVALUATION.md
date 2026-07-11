# CypherStorm Security, Go, Architecture, and TUI Evaluation

**Audit date:** 2026-07-11  
**Audience:** maintainer or implementation model taking over this repository  
**Scope:** all Go source, command wiring, cryptographic and archive formats, credential flow, filesystem behavior, package structure, tests, dependencies, and a future TUI adapter

## 1. Executive decision

CypherStorm must not be used for sensitive data in its currently wired form.

The repository contains two different generations of implementation:

1. **The legacy CLI-wired stack** under `cmd/`, `internal/pipeline`, `internal/encryption`, `internal/keyman`, and `utils`. It has critical cryptographic defects.
2. **A newer, substantially safer but unfinished v1 stack** under `internal/archive`, `internal/compress`, `internal/crypto`, `internal/format`, `internal/fsutil`, `internal/kdf`, and `internal/report`. It is not wired into the CLI and still has security/correctness defects that must be fixed before release.

The working tree is in a partial migration state. The executable does not compile because current callers still import deleted packages (`internal/archiver` and `internal/compression`). This is not a cosmetic problem: no current end-to-end protect or restore path is runnable.

### Direct answers

- **Does password protection work?** No. The currently wired legacy password flow cannot restore its own output. Protect and restore each generate a new random salt, but the salt is never stored. The same password therefore derives a different key during restore.
- **Is the legacy encryption secure with a raw 32-byte key?** No. Both legacy AEAD implementations reuse one nonce for all chunks. AES-GCM and XChaCha20-Poly1305 confidentiality and integrity guarantees are invalid after nonce reuse.
- **Is the new v1 engine ready?** No. Its overall design is much better, but it is disconnected from the CLI, the repository does not build, hostile header values can force extreme Argon2 work before authentication, single-file archiving silently archives nothing, and transactional/resource-limit issues remain.
- **Should TUI work begin now?** Only after the v1 application layer builds and passes protect/restore round trips. The TUI must be an adapter over a UI-neutral application service. It must not call Cobra commands, duplicate pipeline logic, or expose passwords as command-line arguments.

## 2. Evidence and verification performed

Observed commands and outcomes:

- `go test ./...`: failed during package setup because `cmd/protect.go`, `cmd/restore.go`, and legacy pipelines import nonexistent internal packages. The command also timed out while other package work continued.
- `go test -timeout 30s ./internal/crypto`: failed by timeout. `TestDecrypt_TamperedHeader_Fails` mutates an Argon2 header byte, and restore performs attacker-selected Argon2 work before header authentication.
- `go test -timeout 30s ./internal/archive`: passed.
- `go test -timeout 30s ./internal/compress`: passed.
- `go test -timeout 30s ./internal/fsutil`: passed.
- `go test -timeout 30s ./internal/format`: package built; it currently has no tests.
- Focused security review confirmed that narrow wrong-password and credential-kind v1 crypto tests pass, but this does not establish an end-to-end CLI round trip.

Not established:

- No successful whole-program build.
- No end-to-end CLI protect/restore execution.
- No dependency vulnerability scan; `govulncheck` was not available/exercised against a buildable program.
- No Windows runtime testing, crash-durability verification, OS keychain integration, or terminal password-prompt behavior.

## 3. Security findings

Severity meanings:

- **Critical:** confidentiality/integrity failure, guaranteed data loss, or no buildable executable.
- **High:** realistic data loss, denial of service, unsafe filesystem mutation, or release-blocking correctness defect.
- **Medium:** exploitable local/resource issue, unsafe operational behavior, or important defense missing.
- **Low:** hardening or limited correctness issue that should still be fixed before declaring the product mature.

### S-01 — Critical: legacy AEAD nonce reuse destroys the security claim

**Affected:**

- `internal/encryption/aes.go:29-61`
- `internal/encryption/xchacha20.go:24-55`

**Evidence:** each encryptor generates one nonce before entering its chunk loop and passes that same nonce to every `Seal` call.

**Impact:** repeated nonce use repeats the encryption keystream and reuses one-time authentication state. For AES-GCM this is catastrophic; XChaCha20-Poly1305 also requires nonce uniqueness. An attacker can learn relationships between plaintext chunks and may forge authenticated content.

**Required fix:** delete the legacy format after all callers are migrated. Do not attempt an in-place compatibility patch. Use the v1 record engine, which derives a per-file key and a unique monotonic nonce for each framed record.

### S-02 — Critical: password archives made by the legacy flow are irrecoverable

**Affected:**

- `cmd/protect.go:30-49`
- `cmd/restore.go:30-49`
- `utils/password.go:10-30`
- `internal/keyman/keyman.go:24-39`

**Protect trace:** password string -> `DeriveKeyFromPassword` -> fresh random 16-byte salt -> Argon2id key -> legacy cipher writes only nonce and ciphertext.

**Restore trace:** same password string -> a second fresh random 16-byte salt -> a different Argon2id key -> AEAD authentication failure.

**Impact:** permanent data loss for every password-mode legacy artifact. The correct password cannot reproduce the key.

**Required fix:** credential resolution must return a typed password credential, not a pre-derived key. The v1 format layer must generate and serialize the salt and KDF policy. Restore must read those values before deriving the key. The new `internal/kdf.Credential` and `internal/crypto` format implement the correct basic model but are not wired.

### S-03 — Critical: the executable does not build

**Affected:**

- `cmd/protect.go:7`
- `cmd/restore.go:7`
- `internal/pipeline/protect.go:8-9`
- `internal/pipeline/restore.go:8-9`
- `internal/pipeline/benchmark.go:11`

**Evidence:** current source imports deleted `internal/compression` and `internal/archiver` packages. Their replacements are `internal/compress` and `internal/archive`, with different APIs.

**Impact:** no current CLI path can be released or tested end to end. The newer security controls are dead code from the executable's perspective.

**Required fix:** perform one clean cutover through a new application orchestration layer. Do not recreate shims named after the deleted packages.

### S-04 — High: hostile v1 headers can trigger extreme Argon2 CPU/memory before authentication

**Affected:**

- `internal/format/format.go:212-245`
- `internal/kdf/kdf.go:72-107`
- `internal/crypto/engine.go:202-229`
- `internal/crypto/engine_test.go:104-111`

**Evidence:** decoded Argon2 time, memory, parallelism, and key-length fields are only checked for nonzero values. They are attacker-controlled until the header is authenticated, yet restore passes them to `argon2.IDKey`. The existing tamper test changes an Argon2 time byte despite its comment saying it changes the salt. A focused 30-second package test timed out inside Argon2.

**Impact:** a tiny file can request enormous memory or CPU, hanging or terminating the process before a wrong credential or invalid header can be reported.

**Required fix:** define fixed or tightly bounded v1 parameters and reject values before calling Argon2. At minimum:

- key length must equal 32;
- time must have a small explicit maximum;
- memory KiB must have an explicit operator-safe maximum;
- parallelism must have a small explicit maximum;
- encryption options must be checked against the same policy;
- unit tests should use cheap valid parameters, with one production-default smoke test.

The exact maximums are a product/resource-policy decision, but unbounded values are prohibited.

### S-05 — High: predictable legacy temporary paths expose plaintext and permit collisions/symlink attacks

**Affected:**

- `internal/pipeline/protect.go:20-67`
- `internal/pipeline/restore.go:20-67`

**Evidence:** every process uses fixed names under the system temp directory: `archive.tar`, `archive.tar.cmp`, `decrypted.tar.cmp`, and `decrypted.tar`. `os.Create` follows existing symlinks and uses the process umask. Cleanup is success-dependent and is attempted while deferred handles may still be open.

**Impact:** concurrent operations corrupt each other; local attackers can redirect writes through pre-created symlinks; plaintext intermediates may be world-readable; failures leave sensitive material on disk.

**Required fix:** use a unique 0700 workspace per operation, exclusive 0600 files, immediate deferred workspace cleanup, and explicit per-stage closes. `internal/fsutil.Workspace` is the intended base. Prefer streaming where it does not complicate finalization or transactional publication.

### S-06 — High: direct final-path writes can destroy input/existing output and publish partial ciphertext

**Affected:** `internal/pipeline/protect.go:47-61`.

**Evidence:** `os.Create(outputPath)` truncates before encryption succeeds. There is no same-path/containment validation, overwrite policy, or atomic commit.

**Impact:** input equal to output can destroy the source; a failed encryption can replace a valid existing artifact with partial bytes.

**Required fix:** validate path relationships before mutation; reject existing output by default unless overwrite is explicit; write a same-directory exclusive temporary file with mode 0600; close/finalize successfully; publish atomically. Enforce no-replace at publication rather than relying solely on a check-then-rename sequence.

### S-07 — High: new archive creation silently loses a single-file input

**Affected:** `internal/archive/create.go:24-40`.

**Evidence:** the `WalkDir` callback skips every entry whose relative path is `.`. For a file root, that is the only entry.

**Impact:** once the v1 stack is wired, protecting a single file can report success while archiving no user content.

**Required fix:** skip `.` only when the source root is a directory. For a file or permitted symlink root, emit one entry using an explicit naming policy such as `filepath.Base(sourceRoot)`. Add single-file and root-symlink round trips.

### S-08 — High: Windows tar path handling is not platform-independent

**Affected:** `internal/archive/extract.go:99-155`.

**Evidence:** tar entry validation splits only on `/`, then later uses OS-specific `filepath` operations. A backslash is a separator on Windows but can survive the tar-name segment validation.

**Impact:** entries such as `..\\outside`, drive-relative forms, or UNC-like names can invalidate the intended traversal model on Windows.

**Required fix:** validate archive names with platform-independent `path` semantics; explicitly reject backslashes, drive/UNC forms, NUL, absolute paths, and every `..` segment before converting to a native path. Add Windows-targeted tests.

### S-09 — High: archive total-size enforcement occurs after writing the violating entry

**Affected:** `internal/archive/extract.go:73-84,173-208`.

**Evidence:** extraction enforces `MaxEntrySize` while copying, but adds and checks the total only after a whole file has been written. The violating file remains.

**Impact:** disk consumption can exceed `MaxTotalSize` by up to one full entry—4 GiB with current defaults—and failed extraction leaves partial output.

**Required fix:** calculate the remaining total budget before each file and copy at most `min(MaxEntrySize, remainingTotal)+1`; remove the current file on any limit violation; stage the entire restore and publish only after success.

### S-10 — High: legacy AES records have no reliable framing

**Affected:** `internal/encryption/aes.go:44-61,87-107`.

**Evidence:** encryption seals each arbitrary `Read` result but concatenates ciphertext records without lengths. Decryption assumes reads will align to `64 KiB + tag`, which `io.Reader` does not guarantee.

**Impact:** valid output can be unrecoverable depending on short-read behavior. This is independent of nonce reuse.

**Required fix:** delete this decoder with the legacy format. The v1 length-prefixed record format and `io.ReadFull` behavior are the correct design.

### S-11 — High: restore is not transactional

**Affected:**

- `internal/pipeline/restore.go:45-66`
- `internal/archive/extract.go:18-96`

**Evidence:** extraction mutates the requested destination entry by entry. Late authentication, decompression, archive, metadata, or resource-limit errors can leave a partial tree.

**Impact:** users cannot tell whether a destination is complete; existing data can be mixed with failed restore output.

**Required fix:** require a nonexistent/empty destination according to a documented policy; decrypt/decompress/extract into private staging; apply final metadata; rename/publish only after full success. Never implicitly merge a restore into an existing tree.

### S-12 — Medium: legacy decoders allocate attacker-controlled lengths

**Affected:**

- `internal/encryption/aes.go:77-84`
- `internal/encryption/xchacha20.go:67-89`

Nonce and XChaCha chunk lengths are read from input and allocated without exact-size/max checks. Malformed files can force huge allocations. Reject legacy input; retain explicit pre-allocation limits in the v1 record format.

### S-13 — Medium: legacy formats do not commit stream completion or sequence

**Affected:**

- `internal/encryption/aes.go:66-109`
- `internal/encryption/xchacha20.go:61-103`

There is no authenticated final record or total-count commitment. XChaCha can accept removal of complete tail chunks; records are not bound to sequence positions. Use the v1 sequence-number AAD and authenticated final record.

### S-14 — Medium: decompression and restoration need end-to-end resource limits

**Affected:** `internal/pipeline/restore.go:39-60` and future application orchestration.

Archive entry limits do not alone bound bytes emitted by decompression before tar parsing. A valid encrypted compression bomb can consume disk/CPU. Stream decompression into bounded extraction where possible, enforce context cancellation, and keep all intermediate output in disposable private staging.

### S-15 — Medium: archive extraction has check-then-use symlink races

**Affected:** `internal/archive/extract.go:128-180,211-220`.

`Lstat` validation and later create/mkdir/symlink operations are separate path operations. A local process that can mutate the destination may replace a checked component in between. Preferred fix: descriptor-relative no-follow operations (`openat`/`mkdirat`, platform equivalents). Minimum acceptable mitigation: always use an inaccessible fresh 0700 staging root and atomically publish it.

### S-16 — Medium: passwords are exposed through CLI arguments

**Affected:** `cmd/protect.go:58-59`, `cmd/restore.go:58-59`, `cmd/root.go:10-17`.

A `--password` value can appear in shell history and process listings and is retained in package-global strings. The future CLI should default to a hidden TTY prompt, confirm on protect, and support stdin/file-descriptor input for automation. The TUI password field must be masked and must never turn the secret into a Cobra argument.

### S-17 — Medium: key-file semantics are ambiguous

**Affected:** `utils/password.go:13-27` and command flag descriptions.

The error mentions nonexistent `--password-file`; the real flag is `--key-file-path`; descriptions call it a password file; implementation uses its bytes directly as an AEAD key. Define a raw-key file as exactly 32 binary bytes, separately model a password credential, reject non-regular files and wrong lengths, and define/warn about unsafe file permissions.

### S-18 — Medium: directory metadata is applied too early during extraction

**Affected:** `internal/archive/extract.go:67-71,158-170`.

Read-only directory modes can prevent later child creation, and creating children changes directory mtimes after the timestamp was restored. Create with temporary owner permissions; collect metadata; apply directory modes/times in reverse depth order after successful extraction.

### S-19 — Low/integration invariant: v1 decrypt writes records before authenticating the final record

**Affected:** `internal/crypto/engine.go:238-317`.

Each data record is authenticated before write, but overall stream completion is only known after the final record. This is acceptable only if callers write to private staging and never publish partial plaintext on failure. Make this an explicit application-layer invariant and test it.

### S-20 — Low/integration invariant: no-overwrite validation and rename are racy

**Affected:** `internal/fsutil/fsutil.go:115-165`.

A target may be created after validation and before `os.Rename`; Unix rename may replace it. If “no overwrite” is the contract, publication needs an atomic no-replace primitive or equivalent link-based sequence.

## 4. Positive security controls in the unfinished v1 stack

These are worth keeping:

- Fresh random 32-byte per-file salt.
- Argon2id for passwords and exact-length validation for raw keys.
- HKDF-SHA-256 per-file, cipher-domain-separated keys.
- Monotonic per-record nonces with overflow rejection.
- Header bytes, record type, and record index included as AEAD associated data.
- Authenticated final record committing record and byte counts.
- Rejection of unknown versions/IDs, malformed record sizes, noncontiguous indices, missing/duplicated final records, count mismatches, and trailing bytes.
- Header and record allocation caps.
- Archive checks for `/`-style traversal, escaping symlinks, unsupported special types, and entry/size/depth totals.
- 0700 workspaces and 0600 staging files in `internal/fsutil`.
- Context-aware crypto/archive APIs.

These controls are not product guarantees until the application/CLI uses them and end-to-end tests pass.

## 5. Go correctness and anti-pattern findings

### G-01 — Critical: partial migration and duplicate architecture

The codebase simultaneously contains deleted legacy package imports, legacy concrete implementations, and new replacement packages. There are multiple identifier registries and factories. This creates drift and makes a clean build impossible.

**Decision:** one atomic cutover. Do not preserve aliases or compatibility wrappers. After all callers move, delete:

- `internal/pipeline`
- `internal/encryption`
- `internal/keyman`
- `utils`
- legacy `constants` duplicated by typed package IDs
- placeholder cipher IDs in `internal/report`

### G-02 — Medium: `log.Fatal` and `os.Exit` occur below the process boundary

**Affected:** all current command callbacks and `cmd/root.go`.

`log.Fatal` calls `os.Exit`, skips deferred cleanup, prevents in-process tests, and cannot be rendered cleanly by a TUI.

**Fix:** use Cobra `RunE`; return errors. `main` is the only process-exit boundary.

### G-03 — Medium: package-global Cobra commands and flags

**Affected:** `cmd/root.go`, `cmd/protect.go`, `cmd/restore.go`, `cmd/hash.go`, `cmd/benchmark.go`, `cmd/version.go`.

Shared globals and `init` registration create a stateful singleton command tree. Repeated tests retain state; protect and restore bind to the same flag variables; dependency injection is difficult.

**Fix:** `NewRoot` and explicit child constructors. Each command owns a local option struct captured by its closure. Inject the application service, streams, and version.

### G-04 — High: benchmark panics if every combination fails

**Affected:** `internal/pipeline/benchmark.go:60-76,105-134`.

Failures are skipped, then `timeResults[0]` and `ratioResults[0]` are indexed unconditionally. Migrate to `internal/report.Report`, preserve each failure, and return a clear aggregate error for zero successes without panicking.

### G-05 — Medium: business logic prints directly to stdout

**Affected:** legacy protect, restore, hash, and benchmark pipelines.

Business logic should return structured results and emit optional UI-neutral progress events. CLI and TUI adapters decide how to render. This is required for testability and shared CLI/TUI behavior.

### G-06 — Medium: hash traversal lacks a safe filesystem-node policy

**Affected:** `internal/pipeline/hasher.go:12-58`.

It hashes every non-directory node, follows symlinks when opened, may block on FIFOs, prints results directly, ignores close errors, and loses wrapping on some errors.

**Fix:** use `WalkDir`; process regular files only unless a different policy is explicit; define symlink behavior; accept context; return structured `{Path, Digest}` values or invoke a typed callback; wrap errors with `%w`.

### G-07 — Medium: benchmark mixes too many responsibilities

**Affected:** `internal/pipeline/benchmark.go`.

It combines registries, map iteration, factories, filesystem staging, timing, progress output, reporting, and summary selection. Map iteration makes order nondeterministic.

**Fix:** application benchmark orchestration consumes deterministic codec/cipher registries and returns report data. Rendering is a separate adapter. Inject a clock/runner only where tests need it.

### G-08 — Medium: close/finalization and short-write errors are discarded

Legacy pipelines defer closes but report success without observing close failures. Compression writer `Close` is finalization, not optional cleanup. Several legacy writes check errors but not short counts.

**Fix:** close stage resources explicitly at phase boundaries; combine cleanup errors where relevant; use `io.Copy`/`io.WriteString` or exact-write helpers; publish only after finalization succeeds.

### G-09 — Medium: report renderer silently ignores Excel errors

**Affected:** `internal/report/excel.go:26-115`.

Cell, width, coordinate, and workbook close errors are ignored even though package comments promise error propagation. Nil failure errors can panic in Excel and text renderers.

**Fix:** return and wrap every third-party error; close the workbook; enforce non-nil failure errors at model construction or render defensively.

### G-10 — Medium: algorithm/domain identifiers are duplicated

**Affected:** `constants`, legacy factories, `internal/compress`, `internal/crypto`, `internal/format`, `internal/report/cipher.go`.

There are mutable exported string variables, typed IDs, wire IDs, map keys, and a report placeholder type.

**Fix:** each capability package owns one typed human-facing ID and deterministic registry. `format` owns only stable wire IDs and explicit translation. Reports consume result values rather than owning a second registry.

### G-11 — Low: interface placement and presentation leakage

`hashing.Hasher` returns presentation-ready hex and stateless implementations are allocated behind pointer constructors. Prefer standard-library primitives or an application-level hashing function returning bytes/structured results. Keep interfaces such as `compress.Codec` where they represent a genuine lifecycle/extension seam. Define mocking interfaces at consumers, not producers.

### G-12 — Low: naming/documentation inconsistencies

Legacy names such as `AesGcmEncryptor`, `hashfn`, underscore-style identifiers, and undocumented exported internal APIs are nonidiomatic. Prefer `AESGCM`, `hashFile`, and typed camel-case constants. Do not spend time documenting legacy code that should be deleted; preserve the stronger documentation style in new packages.

### G-13 — Low: repository documentation and automation are stale

- `AGENTS.md` still references deleted old package paths and says no tests exist.
- `README.md` links a missing `OVERHAUL.md`.
- Makefile builds `cli`; README builds `cypherstorm`.
- `eudia.py` appears unrelated to this Go cryptography repository and should be moved or removed by its owner.
- `go.mod` marks Excelize indirect even though new report code imports it directly; tidy is blocked until imports compile.

Do not delete unrelated files without confirming ownership. Update docs/automation only after the implementation cutover works.

## 6. Go strengths worth preserving

- `internal/compress.Codec` is a meaningful streaming interface with explicit finalization ownership.
- Codec factories fail closed and `AllCodecs` provides deterministic order.
- The v1 record format uses exact reads, checks short writes, and bounds allocations.
- New crypto and archive APIs accept `context.Context`.
- Archive creation closes each opened descriptor per iteration instead of deferring every file until traversal ends.
- New packages generally use contextual `%w` error wrapping.
- `internal/fsutil` separates workspace creation, path validation, and atomic publication.
- New report selection handles zero successful runs without indexing an empty slice.
- Focused package tests exist for archive, compression, crypto, filesystem utilities, hashing, and reports.

## 7. Target architecture for one binary with CLI and TUI

```text
cmd/
  cypherstorm/
    main.go                    # only os.Exit boundary
internal/
  app/
    service.go                 # concrete Service and dependencies
    protect.go                 # context + request/result orchestration
    restore.go
    hash.go
    benchmark.go
    events.go                  # UI-neutral progress events
  ui/
    cli/
      root.go                  # NewRoot(service, streams, version)
      protect.go
      restore.go
      hash.go
      benchmark.go
      version.go
    tui/
      run.go                   # terminal lifecycle only
      model.go                 # top-level state machine
      menu.go
      protect.go
      restore.go
      hash.go
      benchmark.go
      result.go
      styles.go
  archive/                     # safe tar streaming
  compress/                    # codecs and typed IDs
  crypto/                      # v1 record engine and suites
  format/                      # wire contract only
  kdf/                         # typed credentials and bounded policy
  fsutil/                      # private staging and atomic commit
  hashing/                     # digest operations
  report/                      # pure result/rendering code
  testutil/
```

Dependency direction:

```text
cmd/cypherstorm -> internal/ui/cli -> internal/app
cmd/cypherstorm -> internal/ui/tui -> internal/app
internal/app -> archive + compress + crypto + format + kdf + fsutil + hashing + report
crypto -> format + kdf
```

Rules:

- CLI and TUI never import each other.
- Capability packages never import UI packages.
- TUI never shells out to the CLI and never builds Cobra argument arrays.
- `app` never prints, reads the terminal, or depends on Bubble Tea.
- Prefer a concrete `*app.Service`; define narrow interfaces in adapters only where tests need a fake.
- Do not add a dependency-injection framework.

## 8. Application API contract required before TUI

Illustrative contract; names may change, behavior may not:

```go
type Credential struct {
    Kind     CredentialKind
    Password []byte
    RawKey   []byte
}

type ProtectRequest struct {
    InputPath  string
    OutputPath string
    Credential Credential
    Cipher     crypto.CipherID
    Codec      compress.CompressionID
    Overwrite  bool
}

type RestoreRequest struct {
    InputPath  string
    OutputPath string
    Credential Credential
    Overwrite  bool
}

type HashRequest struct {
    InputPath string
    Algorithm hashing.ID
}

type BenchmarkRequest struct {
    InputPath  string
    OutputPath string
}

type Service struct { /* explicit capability dependencies */ }

func (s *Service) Protect(ctx context.Context, req ProtectRequest, sink EventSink) (ProtectResult, error)
func (s *Service) Restore(ctx context.Context, req RestoreRequest, sink EventSink) (RestoreResult, error)
func (s *Service) Hash(ctx context.Context, req HashRequest, sink EventSink) ([]HashResult, error)
func (s *Service) Benchmark(ctx context.Context, req BenchmarkRequest, sink EventSink) (report.Report, error)
```

`RestoreRequest` deliberately has no cipher, codec, or KDF parameters. Restore reads authenticated metadata from the v1 header and selects implementations internally.

Progress must be typed and UI-neutral, for example:

```go
type Event struct {
    Phase   Phase
    Current int64
    Total   int64 // zero when unknown
    Detail  string
}

type EventSink func(Event)
```

The event sink must not block crypto/I/O indefinitely. Define whether delivery is synchronous and cheap or buffered/coalesced by the adapter. Cancellation comes from `context.Context`.

## 9. TUI design

### 9.1 Framework choice

Use Bubble Tea as the state-machine/runtime, Bubbles for standard controls, and Lip Gloss for styling. Because this repository declares Go 1.23.2, select versions whose `go.mod` supports Go 1.23. Do not blindly adopt Bubble Tea v2: its current main branch uses module path `charm.land/bubbletea/v2` and declares Go 1.25. Keep the dependency choice explicit and pinned after checking the selected release.

Primary references:

- Bubble Tea repository: https://github.com/charmbracelet/bubbletea
- Bubble Tea v2 upgrade guide: https://github.com/charmbracelet/bubbletea/blob/main/UPGRADE_GUIDE_V2.md
- Current v2 module declaration: https://raw.githubusercontent.com/charmbracelet/bubbletea/main/go.mod

A conservative Go-1.23-compatible implementation can use the latest compatible v1 releases rather than raising the entire project's Go requirement merely for the UI.

### 9.2 Entry behavior

Required interface:

- `cypherstorm` with no subcommand launches the full-screen TUI by default when both stdin and stdout are interactive terminals.
- `cypherstorm tui` remains an explicit equivalent for discoverability, desktop launchers, documentation, and callers that want to state intent.
- Existing noninteractive subcommands remain first-class and use the same `app.Service`.
- `cypherstorm --help`, `cypherstorm help`, and every explicit subcommand remain normal Cobra paths and must never initialize terminal UI state.
- With no subcommand in a noninteractive environment, do not emit terminal escape sequences or wait for input. Print concise help to stdout and return a deterministic successful exit unless a stricter non-TTY policy is deliberately documented.
- Detect terminal capability at the executable/UI boundary; do not put terminal detection in `internal/app`.

### 9.3 Screen/state model

```text
Home
  -> Protect form -> Confirm -> Running -> Success/Error
  -> Restore form -> Confirm -> Running -> Success/Error
  -> Hash form    -> Running -> Results
  -> Benchmark form -> Confirm -> Running -> Results
  -> Help/About
```

Top-level states should be explicit enums, not several loosely related booleans. Each operation form owns local field state and validation errors. Returning to Home clears secret buffers and cancels active work when the user confirms cancellation.

### 9.4 Protect form

Fields:

- input path;
- output path;
- credential kind: password or raw key file;
- masked password and confirmation when password is selected;
- key-file path when raw key is selected;
- compression codec;
- cipher suite;
- overwrite toggle, default false.

Validation before execution:

- required paths;
- input existence/type policy;
- input/output containment and same-path rejection;
- password nonempty and confirmation match;
- key file regular and exactly 32 bytes;
- selected IDs supported;
- existing-output policy explicit.

Do not inspect or derive the password in the view renderer. Clear mutable password field buffers after the operation or when leaving the form, best-effort, while documenting Go memory limitations.

### 9.5 Restore form

Fields:

- protected input path;
- destination path;
- credential kind;
- masked password or raw-key path;
- overwrite/replace behavior only if the application has a safe documented policy.

Do not ask for cipher or codec. Those are authenticated v1 metadata. Show a clear error if credential kind does not match the file's KDF.

### 9.6 Hash and benchmark forms

Hash displays structured path/digest rows with scrolling and optional copy/export behavior. It must not parse stdout from an old pipeline.

Benchmark displays deterministic combinations, current phase, successes/failures, and final report paths. All-combination failure must render an error/report, never panic.

### 9.7 Asynchronous execution and cancellation

All filesystem/Argon2/compression operations must run in a Bubble Tea command, not in `Update` or `View`. A command invokes one `app.Service` method with a cancellable context and sends typed completion/progress messages back to the model.

Required behavior:

- UI remains responsive during Argon2 and large-file work.
- `Esc`/`Ctrl+C` on a running screen requests cancellation and waits for cleanup; it must not publish partial output.
- A second operation cannot start while one is active.
- Late messages from a cancelled previous operation carry an operation ID and are ignored.
- Progress updates are coalesced/bounded so a fast producer cannot grow memory without limit.
- Terminal restoration occurs on success, error, panic boundary, and cancellation.

### 9.8 Error and secret rendering

- Render actionable contextual errors, but never include password/raw-key bytes.
- Wrong password and corrupted ciphertext may intentionally share an authentication-failure message to avoid misleading claims.
- Avoid printing secret-bearing request structs with `%+v`.
- TUI logs, if added, must redact credentials and default to off.
- Key-file path may be shown; key-file contents must not.

### 9.9 Accessibility and terminal behavior

- Keyboard-only operation with visible focus.
- Do not rely on color alone for status.
- Respect narrow terminals with a minimum-size message and scrollable content.
- Support non-truecolor terminals through adaptive colors.
- Include concise key help on every screen.
- Disable mouse-only actions; mouse support may be additive.

## 10. TUI tests and acceptance criteria

### Model/state tests

Use deterministic `Init`/`Update` tests with a fake narrow service:

- Home navigation reaches each form.
- Tab/shift-tab and arrow behavior follows visible field order.
- Protect cannot submit mismatched/empty passwords.
- Credential-kind switch hides and clears the inactive secret source.
- Restore never exposes cipher/codec controls.
- Service errors move to error state and preserve nonsecret form context.
- Success moves to result state with expected output path/result rows.
- Cancellation invokes the cancel function exactly once and ignores stale messages.
- Window resize changes layout without losing field values.
- Secret text is absent from rendered views and serialized debug output.

### Application integration tests used by both adapters

- Password and raw-key protect/restore round trips.
- Both ciphers × all codecs × empty, one-byte, record-boundary, multi-record, single-file, and directory input.
- Wrong password, wrong credential kind, tampered header/record/final record, truncation, reorder, duplicate, and trailing bytes.
- Existing output preserved on every failure.
- Failed restore leaves no destination/partial tree.
- Cancellation during archive, compression, encryption, decryption, and extraction cleans staging.
- Two concurrent operations use independent workspaces.

### Focused terminal smoke test

After the application layer and model tests pass:

1. Build the binary.
2. Launch bare `cypherstorm` in a pseudo-terminal and assert that the TUI Home view is the initial view.
3. Protect a temporary one-file input with a prompted password.
4. Restore it through the TUI with the same password.
5. Compare recovered bytes.
6. Repeat one raw-key case.
7. Confirm no password appears in process arguments or captured screen output.
8. Confirm terminal mode is restored after normal exit and cancellation.
9. Run bare `cypherstorm` with piped stdin/stdout and assert that it prints plain help, exits without waiting, and emits no terminal-control sequences.
10. Assert that `cypherstorm --help` and explicit CLI subcommands never start the TUI, even in a terminal.

## 11. Recommended migration sequence

The order is intentional. Do not start TUI rendering before the application contract is stable.

### Phase 0 — make tests bounded and restore a trustworthy feedback loop

1. Add strict Argon2 policy bounds before KDF invocation.
2. Fix `TestDecrypt_TamperedHeader_Fails` so its mutation matches its intent and cannot request extreme KDF work.
3. Use cheap valid KDF settings in broad unit matrices; retain one production-default smoke test.
4. Add direct `internal/format` and `internal/kdf` boundary tests.

**Exit criterion:** focused v1 package tests finish predictably; no hostile header can invoke out-of-policy Argon2 work.

### Phase 1 — fix core correctness before wiring

1. Fix single-file/root-symlink archive behavior.
2. Fix pre-write total-size enforcement.
3. defer directory metadata application until children are complete.
4. define Windows path policy and reject platform-ambiguous names.
5. define overwrite, symlink, destination, and resource-limit policies.
6. propagate report/Excel errors and close workbook resources.

**Exit criterion:** focused archive/format/crypto/fsutil/report tests pass and cover each boundary.

### Phase 2 — add `internal/app`

1. Introduce context-based request/result APIs and typed progress events.
2. Implement transactional protect with private staging and atomic final publication.
3. Implement transactional restore with authenticated metadata auto-selection and staged destination publication.
4. Implement structured hash traversal with an explicit filesystem-node policy.
5. Implement deterministic benchmark orchestration with complete failure reporting.

**Exit criterion:** application-level password/raw-key round-trip matrix passes; failures and cancellation publish nothing partial.

### Phase 3 — rebuild the CLI adapter

1. Replace global Cobra commands with `NewRoot` and child constructors.
2. Use local option structs and `RunE`.
3. Add hidden interactive password prompting and typed raw-key resolution.
4. Keep `main` as the only exit boundary.
5. Cut all commands over in one change.
6. Delete legacy pipelines, encryption, key manager, utility helper, duplicate constants, and report placeholder types.

**Exit criterion:** repository builds; CLI help and focused protect/restore/hash/benchmark tests pass; no executable path imports legacy code.

### Phase 4 — dependency and repository cleanup

1. Run `go mod tidy` only after imports settle.
2. Run `govulncheck ./...` on the buildable program and assess reachable findings.
3. Review dependency updates; do not combine unneeded major upgrades with the security cutover.
4. Decide whether XLSX is worth its binary/supply-chain cost; CSV/text is simpler if XLSX is not required.
5. Update README, AGENTS, Makefile, security notice, and format compatibility documentation to observed behavior.

**Exit criterion:** module metadata is synchronized; documentation matches the executable; security claims have tests.

### Phase 5 — add the TUI adapter

1. Pin a Go-1.23-compatible Bubble Tea/Bubbles/Lip Gloss set.
2. Implement the state machine and forms over `app.Service`.
3. Add masked secret entry, operation IDs, cancellation, bounded progress, responsive layout, and accessible status rendering.
4. Add model tests and pseudo-terminal/non-TTY entrypoint smoke tests.
5. Make the TUI Home view the default for a bare interactive `cypherstorm` invocation; retain `cypherstorm tui` as an explicit alias and preserve plain help for bare non-TTY execution.

**Exit criterion:** TUI and CLI produce identical application behavior; both password and raw-key TUI round trips pass; cancellation and errors leave no partial output and restore terminal state.

## 12. Smaller-model implementation rules

Feed the following constraints verbatim to an implementation model:

1. Do not repair or preserve the legacy encrypted format. It is cryptographically unsafe and password artifacts are already unrecoverable.
2. Do not recreate `internal/archiver` or `internal/compression` shims. Complete the cutover to the singular new packages.
3. Do not add the TUI until a UI-neutral `internal/app` layer has tested protect/restore behavior.
4. Do not let CLI or TUI adapters contain archive/compression/crypto orchestration.
5. Do not accept attacker-controlled Argon2 values without strict pre-KDF bounds.
6. Do not write directly to final protected output or restore destination. Stage privately and publish only after complete success.
7. Do not pass passwords in Cobra arguments from the TUI, print them, log request structs containing them, or store them in package globals.
8. Do not ask restore users to select cipher or codec; read authenticated v1 metadata.
9. Do not use map iteration for user-visible/benchmark algorithm ordering.
10. Do not call `log.Fatal` or `os.Exit` outside `main`.
11. Do not ignore compressor/file/workbook close or finalization errors.
12. Do not report completion until focused application round trips, tamper/resource tests, CLI tests, and TUI pseudo-terminal smoke tests pass.
13. A bare interactive `cypherstorm` invocation must open the TUI Home view by default; explicit CLI commands and help must bypass the TUI, and bare non-TTY execution must print plain help without terminal control sequences or blocking.

## 13. Dependency observations

- Several direct dependencies are behind newer releases. Staleness alone is not proof of vulnerability; upgrade only with changelog and regression review.
- `golang.org/x/crypto v0.29.0` supplies Argon2/HKDF/XChaCha. The verified legacy failures are misuse/format-design defects, not a demonstrated primitive failure.
- `github.com/dsnet/compress v0.0.1` is old and deserves a maintenance/provenance review because it provides bzip2 writing.
- XLSX reporting brings a relatively large transitive graph. Keep it only if it is a product requirement.
- `go.mod` cannot be made trustworthy with `go mod tidy` until missing internal imports are removed.

## 14. Release gate

A security-capable release requires all of the following:

- whole repository builds;
- legacy cipher/key/pipeline code is unreachable and deleted;
- bounded v1 KDF policy;
- single-file and directory round trips with password and raw key;
- both ciphers and every supported codec covered;
- authenticated metadata auto-selection on restore;
- transactional protect and restore;
- no predictable temporary names or partial publication;
- malicious archive and resource-bound tests;
- CLI secrets are prompted, not passed by default in argv;
- focused dependency vulnerability assessment;
- README security claims exactly match tested behavior.

TUI release additionally requires responsive asynchronous execution, cancellation cleanup, masked secret handling, model tests, and a real pseudo-terminal protect/restore smoke test.
