package fsutil

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestNewWorkspaceCreatesPrivateDir(t *testing.T) {
	ws, err := NewWorkspace()
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	defer func() {
		if cerr := ws.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	}()

	info, err := os.Stat(ws.Root())
	if err != nil {
		t.Fatalf("stat workspace root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("workspace root %q is not a directory", ws.Root())
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("expected 0700 workspace permissions, got %v", perm)
		}
	}
}

func TestWorkspaceCreateFileWritesUnderRoot(t *testing.T) {
	ws, err := NewWorkspace()
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	defer func() { _ = ws.Close() }()

	f, err := ws.CreateFile("stage.bin")
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(f.Name())
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected 0600 file permissions, got %v", perm)
		}
	}
}

func TestWorkspaceCreateFileRejectsEscape(t *testing.T) {
	ws, err := NewWorkspace()
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	defer func() { _ = ws.Close() }()

	if _, err := ws.CreateFile("../escape.bin"); err == nil {
		t.Fatalf("expected error for escaping file name")
	}
}

func TestWorkspaceCloseRemovesDirAndReturnsErrors(t *testing.T) {
	ws, err := NewWorkspace()
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}

	root := ws.Root()
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected workspace dir to be removed, stat err: %v", statErr)
	}
}
