//go:build !darwin && !linux && !windows

package fsutil

import (
	"fmt"
	"os"
)

func renameNoReplace(oldPath, newPath string) error {
	info, err := os.Lstat(oldPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("atomic no-replace directory publication is unsupported on this platform")
	}
	if err := os.Link(oldPath, newPath); err != nil {
		return err
	}
	return os.Remove(oldPath)
}
