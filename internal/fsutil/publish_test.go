package fsutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

func TestPublishAtomicSuccessWritesExactBytes(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")
	want := testutil.RandomBytes(t, 4096)

	err := PublishAtomic(finalPath, false, func(tmp *os.File) error {
		n, werr := tmp.Write(want)
		if werr != nil {
			return werr
		}
		if n != len(want) {
			return fmt.Errorf("short write: %d of %d", n, len(want))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("PublishAtomic: unexpected error: %v", err)
	}

	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("final file contents mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workspace dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one entry in workspace dir, got %d: %v", len(entries), entries)
	}
}

func TestPublishAtomicLeavesNoPartialFileOnWriteError(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")
	sentinel := errors.New("boom")

	err := PublishAtomic(finalPath, false, func(tmp *os.File) error {
		if _, werr := tmp.Write([]byte("partial")); werr != nil {
			return werr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got: %v", err)
	}

	if _, statErr := os.Stat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected finalPath to not exist, stat err: %v", statErr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workspace dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no leftover temp files, found: %v", entries)
	}
}

func TestPublishAtomicCleansUpOnPanic(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected write to panic")
			}
		}()
		_ = PublishAtomic(finalPath, false, func(tmp *os.File) error {
			panic("boom")
		})
	}()

	if _, statErr := os.Stat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected finalPath to not exist after panic, stat err: %v", statErr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workspace dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no leftover temp files after panic, found: %v", entries)
	}
}

func TestPublishAtomicSetsFilePermissions(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")

	err := PublishAtomic(finalPath, false, func(tmp *os.File) error {
		_, werr := tmp.Write([]byte("data"))
		return werr
	})
	if err != nil {
		t.Fatalf("PublishAtomic: unexpected error: %v", err)
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatalf("stat final file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %v", perm)
	}
}

func TestPublishAtomicNoReplacePreservesExistingTarget(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(finalPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing target: %v", err)
	}

	err := PublishAtomic(finalPath, false, func(tmp *os.File) error {
		_, writeErr := tmp.Write([]byte("replacement"))
		return writeErr
	})
	if err == nil {
		t.Fatal("expected no-replace publication to fail")
	}
	got, readErr := os.ReadFile(finalPath)
	if readErr != nil || string(got) != "existing" {
		t.Fatalf("existing target changed: got %q err=%v", got, readErr)
	}
}

func TestPublishAtomicOverwriteReplacesCompleteTarget(t *testing.T) {
	dir := testutil.Workspace(t)
	finalPath := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(finalPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing target: %v", err)
	}
	if err := PublishAtomic(finalPath, true, func(tmp *os.File) error {
		_, writeErr := tmp.Write([]byte("replacement"))
		return writeErr
	}); err != nil {
		t.Fatalf("PublishAtomic overwrite: %v", err)
	}
	got, err := os.ReadFile(finalPath)
	if err != nil || string(got) != "replacement" {
		t.Fatalf("target = %q, err=%v", got, err)
	}
}

func TestPublishDirectoryNoReplace(t *testing.T) {
	parent := testutil.Workspace(t)
	staged, err := os.MkdirTemp(parent, ".staged-*")
	if err != nil {
		t.Fatalf("create staged directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staged, "file.txt"), []byte("complete"), 0o600); err != nil {
		t.Fatalf("write staged file: %v", err)
	}
	finalPath := filepath.Join(parent, "restored")
	if err := PublishDirectory(staged, finalPath); err != nil {
		t.Fatalf("PublishDirectory: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(finalPath, "file.txt"))
	if err != nil || string(got) != "complete" {
		t.Fatalf("published file = %q, err=%v", got, err)
	}

	second, err := os.MkdirTemp(parent, ".staged-*")
	if err != nil {
		t.Fatalf("create second staged directory: %v", err)
	}
	if err := PublishDirectory(second, finalPath); err == nil {
		t.Fatal("expected existing directory target to be preserved")
	}
	got, err = os.ReadFile(filepath.Join(finalPath, "file.txt"))
	if err != nil || string(got) != "complete" {
		t.Fatalf("existing directory changed: got %q err=%v", got, err)
	}
}
