package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExtractTar reads a tar stream from r and writes it under destRoot,
// bounded by limits. See the package doc comment for the exact safety and
// bounds policy.
func ExtractTar(ctx context.Context, r io.Reader, destRoot string, limits ExtractLimits) error {
	var err error
	limits, err = limits.withDefaults()
	if err != nil {
		return err
	}

	destRootAbs, err := filepath.Abs(destRoot)
	if err != nil {
		return fmt.Errorf("archive: resolve destination root %q: %w", destRoot, err)
	}
	destRootAbs = filepath.Clean(destRootAbs)

	if err := prepareDestination(destRootAbs); err != nil {
		return err
	}

	tr := tar.NewReader(r)
	entryCount := 0
	var totalSize int64
	var directories []directoryMetadata

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("archive: extraction cancelled: %w", err)
		}

		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("archive: read tar header: %w", err)
		}

		entryCount++
		if entryCount > limits.MaxEntries {
			return fmt.Errorf("archive: extraction exceeds MaxEntries limit (%d)", limits.MaxEntries)
		}

		segments, err := validateEntryName(header.Name)
		if err != nil {
			return err
		}
		if len(segments) > limits.MaxPathDepth {
			return fmt.Errorf("archive: entry %q exceeds MaxPathDepth limit (%d)", header.Name, limits.MaxPathDepth)
		}

		targetPath, err := secureJoin(destRootAbs, segments)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := extractDir(targetPath); err != nil {
				return err
			}
			directories = append(directories, directoryMetadata{
				path:    targetPath,
				mode:    fs.FileMode(header.Mode).Perm(),
				modTime: header.ModTime,
				depth:   len(segments),
			})

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return fmt.Errorf("archive: create parent directory for %q: %w", targetPath, err)
			}
			remainingTotal := limits.MaxTotalSize - totalSize
			maxForEntry := min(limits.MaxEntrySize, remainingTotal)
			written, err := extractRegularFile(ctx, tr, targetPath, header, maxForEntry)
			if err != nil {
				if errors.Is(err, errSizeLimit) {
					if remainingTotal <= limits.MaxEntrySize {
						return fmt.Errorf("archive: extraction exceeds MaxTotalSize limit (%d bytes)", limits.MaxTotalSize)
					}
					return fmt.Errorf("archive: entry %q exceeds MaxEntrySize limit (%d bytes)", header.Name, limits.MaxEntrySize)
				}
				return err
			}
			totalSize += written

		case tar.TypeSymlink:
			if err := extractSymlink(targetPath, header, destRootAbs); err != nil {
				return err
			}

		default:
			return fmt.Errorf("archive: unsupported tar entry type %v for %q", header.Typeflag, header.Name)
		}
	}

	if err := applyDirectoryMetadata(directories); err != nil {
		return err
	}
	return nil
}

type directoryMetadata struct {
	path    string
	mode    fs.FileMode
	modTime time.Time
	depth   int
}

func prepareDestination(destRoot string) error {
	info, err := os.Lstat(destRoot)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(destRoot, 0o700); err != nil {
			return fmt.Errorf("archive: create destination root %q: %w", destRoot, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("archive: inspect destination root %q: %w", destRoot, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("archive: destination root %q must be a directory, not a symlink or file", destRoot)
	}
	entries, err := os.ReadDir(destRoot)
	if err != nil {
		return fmt.Errorf("archive: read destination root %q: %w", destRoot, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("archive: destination root %q must be empty", destRoot)
	}
	if err := os.Chmod(destRoot, 0o700); err != nil {
		return fmt.Errorf("archive: secure destination root %q: %w", destRoot, err)
	}
	return nil
}

// validateEntryName uses the platform-independent tar path grammar. It
// rejects names that could gain different meaning after conversion to a
// native path, including backslashes and Windows drive forms.
func validateEntryName(name string) ([]string, error) {
	if name == "" {
		return nil, fmt.Errorf("archive: empty entry name")
	}
	if strings.ContainsRune(name, '\x00') {
		return nil, fmt.Errorf("archive: entry name contains NUL")
	}
	if strings.Contains(name, `\`) {
		return nil, fmt.Errorf("archive: entry name %q contains a backslash", name)
	}
	if pathpkg.IsAbs(name) || isWindowsDrivePath(name) {
		return nil, fmt.Errorf("archive: entry name %q is an absolute or drive path", name)
	}

	raw := strings.Split(name, "/")
	segments := make([]string, 0, len(raw))
	for _, seg := range raw {
		switch seg {
		case "", ".":
			continue
		case "..":
			return nil, fmt.Errorf("archive: entry name %q contains a path traversal segment", name)
		default:
			segments = append(segments, seg)
		}
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("archive: entry name %q resolves to an empty path", name)
	}
	return segments, nil
}

func isWindowsDrivePath(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	first := name[0]
	return first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z'
}

// secureJoin joins segments onto destRootAbs one component at a time,
// refusing to traverse through any path component that already exists as
// a symlink, and verifies the final path is still contained within
// destRootAbs.
func secureJoin(destRootAbs string, segments []string) (string, error) {
	current := destRootAbs
	for _, seg := range segments {
		current = filepath.Join(current, seg)

		fi, err := os.Lstat(current)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("archive: refusing to write through existing symlink at %q", current)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("archive: stat %q: %w", current, err)
		}
	}

	rel, err := filepath.Rel(destRootAbs, current)
	if err != nil {
		return "", fmt.Errorf("archive: resolve relative target path: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive: target path escapes destination root %q", destRootAbs)
	}

	return current, nil
}

func extractDir(targetPath string) error {
	if err := os.MkdirAll(targetPath, 0o700); err != nil {
		return fmt.Errorf("archive: create directory %q: %w", targetPath, err)
	}
	return nil
}

func applyDirectoryMetadata(directories []directoryMetadata) error {
	sort.SliceStable(directories, func(i, j int) bool {
		return directories[i].depth > directories[j].depth
	})
	for _, directory := range directories {
		if !directory.modTime.IsZero() {
			if err := os.Chtimes(directory.path, directory.modTime, directory.modTime); err != nil {
				return fmt.Errorf("archive: set mtime on directory %q: %w", directory.path, err)
			}
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return fmt.Errorf("archive: set mode on directory %q: %w", directory.path, err)
		}
	}
	return nil
}

var errSizeLimit = errors.New("archive size limit exceeded")

// extractRegularFile copies no more than maxBytes+1 bytes. On a limit
// violation or any copy/finalization error it removes the current file.
func extractRegularFile(ctx context.Context, tr *tar.Reader, targetPath string, header *tar.Header, maxBytes int64) (int64, error) {
	f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("archive: create file %q: %w", targetPath, err)
	}

	n, copyErr := io.CopyN(f, contextReader{ctx: ctx, reader: tr}, maxBytes+1)
	closeErr := f.Close()

	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		_ = os.Remove(targetPath)
		return 0, fmt.Errorf("archive: write file %q: %w", targetPath, copyErr)
	}
	if n > maxBytes {
		_ = os.Remove(targetPath)
		return 0, errSizeLimit
	}
	if closeErr != nil {
		_ = os.Remove(targetPath)
		return 0, fmt.Errorf("archive: close file %q: %w", targetPath, closeErr)
	}

	if err := os.Chmod(targetPath, fs.FileMode(header.Mode).Perm()); err != nil {
		return 0, fmt.Errorf("archive: set mode on file %q: %w", targetPath, err)
	}
	if !header.ModTime.IsZero() {
		if err := os.Chtimes(targetPath, header.ModTime, header.ModTime); err != nil {
			return 0, fmt.Errorf("archive: set mtime on file %q: %w", targetPath, err)
		}
	}

	return n, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func extractSymlink(targetPath string, header *tar.Header, destRootAbs string) error {
	if err := validateSymlinkTarget(header.Linkname, targetPath, destRootAbs); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("archive: create parent directory for %q: %w", targetPath, err)
	}
	if err := os.Symlink(filepath.FromSlash(header.Linkname), targetPath); err != nil {
		return fmt.Errorf("archive: create symlink %q: %w", targetPath, err)
	}
	return nil
}

// validateSymlinkTarget rejects platform-ambiguous, absolute, and escaping
// targets. The target need not exist.
func validateSymlinkTarget(linkname, entryTargetPath, destRootAbs string) error {
	if linkname == "" {
		return fmt.Errorf("archive: symlink %q has an empty target", entryTargetPath)
	}
	if strings.ContainsRune(linkname, '\x00') {
		return fmt.Errorf("archive: symlink target contains NUL")
	}
	if strings.Contains(linkname, `\`) {
		return fmt.Errorf("archive: symlink target %q contains a backslash", linkname)
	}
	if pathpkg.IsAbs(linkname) || isWindowsDrivePath(linkname) {
		return fmt.Errorf("archive: symlink target %q must be a portable relative path", linkname)
	}

	resolved := filepath.Clean(filepath.Join(filepath.Dir(entryTargetPath), filepath.FromSlash(linkname)))
	rel, err := filepath.Rel(destRootAbs, resolved)
	if err != nil {
		return fmt.Errorf("archive: resolve symlink target %q: %w", linkname, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("archive: symlink target %q escapes destination root", linkname)
	}
	return nil
}
