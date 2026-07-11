package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
)

// CreateTar walks sourceRoot and writes a tar stream to w. See the
// package doc comment for the exact set of supported entry types and the
// metadata preservation and cancellation policy.
func CreateTar(ctx context.Context, sourceRoot string, w io.Writer) error {
	rootAbs, err := filepath.Abs(sourceRoot)
	if err != nil {
		return fmt.Errorf("archive: resolve source root %q: %w", sourceRoot, err)
	}

	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return fmt.Errorf("archive: lstat source root %q: %w", sourceRoot, err)
	}

	tw := tar.NewWriter(w)

	walkErr := filepath.WalkDir(rootAbs, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("archive: walk %q: %w", path, walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		relPath, err := filepath.Rel(rootAbs, path)
		if err != nil {
			return fmt.Errorf("archive: compute relative path for %q: %w", path, err)
		}
		if relPath == "." {
			if rootInfo.IsDir() {
				// Directory roots are containers: archive their contents,
				// not an extra basename wrapper directory.
				return nil
			}
			// A file or symlink root is the payload itself.
			relPath = filepath.Base(rootAbs)
		}

		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("archive: lstat %q: %w", path, err)
		}

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return writeSymlinkEntry(tw, path, relPath, info)
		case info.IsDir():
			return writeDirEntry(tw, relPath, info)
		case info.Mode().IsRegular():
			return writeRegularEntry(tw, path, relPath, info)
		default:
			return fmt.Errorf("archive: unsupported file type for %q (mode %v)", path, info.Mode())
		}
	})
	if walkErr != nil {
		return fmt.Errorf("archive: create tar from %q: %w", sourceRoot, walkErr)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("archive: finalize tar writer: %w", err)
	}

	return nil
}

func writeDirEntry(tw *tar.Writer, relPath string, info os.FileInfo) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("archive: build header for directory %q: %w", relPath, err)
	}
	header.Name = filepath.ToSlash(relPath) + "/"

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("archive: write header for directory %q: %w", relPath, err)
	}
	return nil
}

func writeSymlinkEntry(tw *tar.Writer, path, relPath string, info os.FileInfo) error {
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("archive: read symlink %q: %w", path, err)
	}
	if err := validateArchivedSymlinkTarget(filepath.ToSlash(relPath), filepath.ToSlash(target)); err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, target)
	if err != nil {
		return fmt.Errorf("archive: build header for symlink %q: %w", relPath, err)
	}
	header.Name = filepath.ToSlash(relPath)

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("archive: write header for symlink %q: %w", relPath, err)
	}
	return nil
}

func validateArchivedSymlinkTarget(entryName, target string) error {
	if target == "" || strings.ContainsRune(target, '\x00') || strings.Contains(target, `\`) {
		return fmt.Errorf("archive: symlink %q has an empty or non-portable target", entryName)
	}
	if pathpkg.IsAbs(target) || isWindowsDrivePath(target) {
		return fmt.Errorf("archive: symlink %q target %q must be a portable relative path", entryName, target)
	}
	resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(entryName), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("archive: symlink %q target %q escapes archive root", entryName, target)
	}
	return nil
}

// writeRegularEntry writes the header and content for a single regular
// file and closes the source file descriptor before returning, so no
// descriptor outlives the loop iteration that opened it.
func writeRegularEntry(tw *tar.Writer, path, relPath string, info os.FileInfo) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("archive: build header for file %q: %w", relPath, err)
	}
	header.Name = filepath.ToSlash(relPath)

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("archive: write header for file %q: %w", relPath, err)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("archive: open file %q: %w", path, err)
	}

	n, copyErr := io.Copy(tw, f)
	closeErr := f.Close()

	if copyErr != nil {
		return fmt.Errorf("archive: write file content for %q: %w", relPath, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("archive: close source file %q: %w", path, closeErr)
	}
	if n != info.Size() {
		return fmt.Errorf("archive: short write for %q (wrote %d of %d bytes): %w", relPath, n, info.Size(), io.ErrShortWrite)
	}

	return nil
}
