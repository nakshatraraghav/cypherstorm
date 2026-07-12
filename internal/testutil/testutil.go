// Package testutil provides shared, non-production helpers for native Go
// tests across the cypherstorm module. It never ships in the built binary.
package testutil

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// Workspace returns a private, 0700 temporary directory scoped to the test.
// It is removed automatically by the testing framework's t.TempDir cleanup.
func Workspace(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("testutil: failed to set workspace permissions: %v", err)
	}
	return dir
}

// RawKey returns count cryptographically random bytes suitable for use as a
// raw-key credential fixture in tests. It never touches the repository.
func RawKey(t *testing.T, count int) []byte {
	t.Helper()

	key := make([]byte, count)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("testutil: failed to generate raw key fixture: %v", err)
	}
	return key
}

// SourceTreeFile describes one regular file to materialize under a
// generated source tree.
type SourceTreeFile struct {
	// RelPath is the file path relative to the tree root; may include
	// nested directories, which are created as needed.
	RelPath string
	Content []byte
	Mode    os.FileMode
}

// SourceTree materializes files under a fresh temporary directory and
// returns the tree root. Intended as protect-input fixtures for
// archive/compress/crypto round-trip tests.
func SourceTree(t *testing.T, files []SourceTreeFile) string {
	t.Helper()

	root := t.TempDir()
	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}

		full := filepath.Join(root, filepath.FromSlash(f.RelPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("testutil: failed to create source tree directory: %v", err)
		}
		if err := os.WriteFile(full, f.Content, mode); err != nil {
			t.Fatalf("testutil: failed to write source tree file: %v", err)
		}
	}
	return root
}

// RandomBytes returns count cryptographically random bytes, useful for
// building plaintext fixtures at specific boundary sizes (recordSize-1,
// recordSize, recordSize+1, etc.).
func RandomBytes(t *testing.T, count int) []byte {
	t.Helper()

	buf := make([]byte, count)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("testutil: failed to generate random bytes fixture: %v", err)
	}
	return buf
}
