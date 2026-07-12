package keymanage

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/security/kdf"
)

func TestLoadValidatesDescriptorPermissionsAndLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.bin")
	key := bytes.Repeat([]byte{0x5a}, kdf.MasterKeySize)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	loaded, err := Load(path)
	if err != nil || !bytes.Equal(loaded, key) {
		t.Fatalf("Load valid key = %x, %v", loaded, err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("chmod exposed key: %v", err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("Load accepted exposed key permissions")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("restore key permissions: %v", err)
		}
	}
	if err := os.WriteFile(path, key[:kdf.MasterKeySize-1], 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a short key")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, bytes.Repeat([]byte{1}, kdf.MasterKeySize), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "key-link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("Load accepted a symlink")
	}
}
