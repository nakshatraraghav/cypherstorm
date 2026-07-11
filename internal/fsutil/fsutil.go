// Package fsutil provides private, per-operation workspaces and atomic
// publication primitives used to keep filesystem side effects safe:
// intermediate plaintext never lives at a predictable path, and a final
// output file is either fully written or not written at all.
//
// Exported API:
//
//	type Workspace struct{ ... }
//	func NewWorkspace() (*Workspace, error)
//	func (w *Workspace) Root() string
//	func (w *Workspace) CreateFile(name string) (*os.File, error)
//	func (w *Workspace) Close() error
//
//	func PublishAtomic(finalPath string, allowOverwrite bool, write func(tmp *os.File) error) error
//	func ValidateOutputTarget(outputPath string, allowOverwrite bool) error
//	func ValidateNoContainment(inputPath, outputPath string) error
//
// Workspace creates a private temporary directory (0700 where the OS
// supports it) for staging intermediate files belonging to a single
// operation. Callers MUST call `defer ws.Close()` immediately after
// NewWorkspace succeeds so the directory is removed even on error paths;
// Close never swallows a removal failure.
//
// PublishAtomic stages content in a same-directory temporary file and
// renames it into place only after the caller-supplied write function and
// the temp file's Close both succeed; on any failure (including a panic
// inside write) the temporary file is removed and finalPath is left
// untouched.
//
// ValidateOutputTarget and ValidateNoContainment perform pre-flight checks
// callers should run before starting an operation that writes to disk.
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Workspace is a private, per-operation staging directory. It is created
// with 0700 permissions where the OS supports them and must be released
// with Close, ideally deferred immediately after creation.
type Workspace struct {
	root string
}

// NewWorkspace creates a new private temporary directory suitable for
// staging intermediate files for a single operation. Callers MUST call
// `defer ws.Close()` immediately after a successful call so the directory
// is guaranteed to be removed, including on error paths.
func NewWorkspace() (*Workspace, error) {
	root, err := os.MkdirTemp("", "cypherstorm-*")
	if err != nil {
		return nil, fmt.Errorf("fsutil: create workspace: %w", err)
	}

	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("fsutil: set workspace permissions: %w", err)
	}

	return &Workspace{root: root}, nil
}

// Root returns the absolute path of the workspace directory.
func (w *Workspace) Root() string {
	return w.root
}

// CreateFile creates a new file directly under the workspace root with
// 0600 permissions. name must be a simple relative name; it must not be
// absolute and must not escape the workspace root via "..".
func (w *Workspace) CreateFile(name string) (*os.File, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("fsutil: workspace file name %q escapes workspace root", name)
	}

	path := filepath.Join(w.root, clean)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("fsutil: create workspace subdirectory for %q: %w", name, err)
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fsutil: create workspace file %q: %w", name, err)
	}
	return f, nil
}

// Close removes the entire workspace directory tree. Errors from the
// underlying removal are returned, never swallowed.
func (w *Workspace) Close() error {
	if err := os.RemoveAll(w.root); err != nil {
		return fmt.Errorf("fsutil: remove workspace %q: %w", w.root, err)
	}
	return nil
}

// PublishAtomic stages content in a temporary file created in the same
// directory as finalPath, invokes write with that temporary file, and only
// on success closes and synchronizes it, sets 0600 permissions, and
// publishes it atomically. When allowOverwrite is false publication uses
// an OS no-replace primitive, so a target created after preflight checks is
// never overwritten.
//
// On any failure - from write, synchronization, closing, permissions, or
// publication - the temporary file is removed and finalPath is left
// untouched. Cleanup is panic-safe.
func PublishAtomic(finalPath string, allowOverwrite bool, write func(tmp *os.File) error) (err error) {
	dir := filepath.Dir(finalPath)

	tmp, err := os.CreateTemp(dir, ".cypherstorm-tmp-*")
	if err != nil {
		return fmt.Errorf("fsutil: create temp file for %q: %w", finalPath, err)
	}
	tmpPath := tmp.Name()

	succeeded := false
	defer func() {
		if !succeeded {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if werr := write(tmp); werr != nil {
		return fmt.Errorf("fsutil: write temp file for %q: %w", finalPath, werr)
	}

	if serr := tmp.Sync(); serr != nil {
		return fmt.Errorf("fsutil: sync temp file for %q: %w", finalPath, serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("fsutil: close temp file for %q: %w", finalPath, cerr)
	}

	if cerr := os.Chmod(tmpPath, 0o600); cerr != nil {
		return fmt.Errorf("fsutil: set permissions on temp file for %q: %w", finalPath, cerr)
	}

	if allowOverwrite {
		err = os.Rename(tmpPath, finalPath)
	} else {
		err = renameNoReplace(tmpPath, finalPath)
	}
	if err != nil {
		return fmt.Errorf("fsutil: publish temp file at %q: %w", finalPath, err)
	}

	succeeded = true
	return nil
}

// PublishDirectory publishes a fully populated same-filesystem staging
// directory without replacing an existing target. Restore intentionally
// has no merge or directory-overwrite mode.
func PublishDirectory(stagedPath, finalPath string) error {
	info, err := os.Lstat(stagedPath)
	if err != nil {
		return fmt.Errorf("fsutil: inspect staged directory %q: %w", stagedPath, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fsutil: staged path %q is not a directory", stagedPath)
	}
	if filepath.Dir(stagedPath) != filepath.Dir(finalPath) {
		return fmt.Errorf("fsutil: staged and final directories must share a parent for atomic publication")
	}
	if err := renameNoReplace(stagedPath, finalPath); err != nil {
		return fmt.Errorf("fsutil: publish directory at %q: %w", finalPath, err)
	}
	return nil
}

// ValidateOutputTarget returns a clear error if outputPath already exists
// and allowOverwrite is false. It also validates that outputPath's parent
// directory either already exists as a directory, or has an existing
// ancestor directory (making it creatable via MkdirAll); it returns an
// error if any existing ancestor in that chain is a regular file rather
// than a directory.
func ValidateOutputTarget(outputPath string, allowOverwrite bool) error {
	if _, err := os.Stat(outputPath); err == nil {
		if !allowOverwrite {
			return fmt.Errorf("fsutil: output target %q already exists", outputPath)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("fsutil: stat output target %q: %w", outputPath, err)
	}

	dir := filepath.Dir(outputPath)
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("fsutil: output parent %q is not a directory", dir)
			}
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("fsutil: stat output parent %q: %w", dir, err)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("fsutil: output parent %q is not creatable: no existing ancestor directory", dir)
		}
		dir = parent
	}
}

// ValidateNoContainment returns an error if outputPath resolves to the
// same path as inputPath, or resolves to a path nested inside inputPath.
// Both paths are resolved with filepath.Abs and filepath.Clean; symlinks
// are resolved best-effort via filepath.EvalSymlinks, falling back to the
// cleaned absolute path when the target does not yet exist.
func ValidateNoContainment(inputPath, outputPath string) error {
	inAbs, err := resolvePath(inputPath)
	if err != nil {
		return fmt.Errorf("fsutil: resolve input path %q: %w", inputPath, err)
	}
	outAbs, err := resolvePath(outputPath)
	if err != nil {
		return fmt.Errorf("fsutil: resolve output path %q: %w", outputPath, err)
	}

	if inAbs == outAbs {
		return fmt.Errorf("fsutil: output path %q is the same as input path %q", outputPath, inputPath)
	}

	rel, err := filepath.Rel(inAbs, outAbs)
	if err != nil {
		return fmt.Errorf("fsutil: compute relative path from %q to %q: %w", inputPath, outputPath, err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("fsutil: output path %q is nested inside input path %q", outputPath, inputPath)
	}

	return nil
}

func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	// abs does not fully exist yet; resolve symlinks on the nearest
	// existing ancestor and rejoin the remaining path components so
	// callers comparing two resolved paths don't see a spurious mismatch
	// caused by an unresolved symlink prefix (e.g. macOS /tmp -> /private/tmp).
	dir := filepath.Dir(abs)
	if dir == abs {
		return abs, nil
	}
	resolvedDir, err := resolvePath(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedDir, filepath.Base(abs)), nil
}
