//go:build windows

package fsutil

import "golang.org/x/sys/windows"

func renameNoReplace(oldPath, newPath string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFile(oldPtr, newPtr)
}
