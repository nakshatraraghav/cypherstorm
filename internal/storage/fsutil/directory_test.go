package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceDirectoryRejectsSymlinkDestinationComponent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("mkdir real parent: %v", err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	staged := filepath.Join(linkParent, "staged")
	final := filepath.Join(linkParent, "final")
	for _, path := range []string{staged, final} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := ReplaceDirectory(staged, final); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("ReplaceDirectory error = %v", err)
	}
}
