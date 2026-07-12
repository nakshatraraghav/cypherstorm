package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReplaceDirectory atomically swaps a same-parent staged directory with an
// existing directory and rolls back if publication fails.
func ReplaceDirectory(stagedPath, finalPath string) error {
	if filepath.Dir(stagedPath) != filepath.Dir(finalPath) {
		return fmt.Errorf("fsutil: staged and final directories must share a parent")
	}
	if err := rejectSymlinkComponents(finalPath); err != nil {
		return err
	}
	info, err := os.Lstat(finalPath)
	if err != nil {
		return fmt.Errorf("fsutil: inspect destination: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fsutil: destination must be a non-symlink directory")
	}
	backup, err := os.MkdirTemp(filepath.Dir(finalPath), ".cypherstorm-backup-*")
	if err != nil {
		return fmt.Errorf("fsutil: reserve backup path: %w", err)
	}
	if err = os.Remove(backup); err != nil {
		return err
	}
	if err = os.Rename(finalPath, backup); err != nil {
		return fmt.Errorf("fsutil: stage existing destination: %w", err)
	}
	if err = os.Rename(stagedPath, finalPath); err != nil {
		rollback := os.Rename(backup, finalPath)
		if rollback != nil {
			return fmt.Errorf("fsutil: publish replacement: %v; rollback failed: %w", err, rollback)
		}
		return fmt.Errorf("fsutil: publish replacement: %w", err)
	}
	if err = os.RemoveAll(backup); err != nil {
		return fmt.Errorf("fsutil: remove replaced destination backup: %w", err)
	}
	return nil
}

func rejectSymlinkComponents(target string) error {
	for current := filepath.Clean(target); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("fsutil: inspect destination component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fsutil: destination component %q must not be a symlink", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}
