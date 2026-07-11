// Package archive provides safe, bounded tar archive creation and
// extraction used as the container format for protect/restore operations.
//
// Exported API:
//
//	func CreateTar(ctx context.Context, sourceRoot string, w io.Writer) error
//	func ExtractTar(ctx context.Context, r io.Reader, destRoot string, limits ExtractLimits) error
//
//	type ExtractLimits struct {
//	    MaxEntries   int
//	    MaxEntrySize int64
//	    MaxTotalSize int64
//	    MaxPathDepth int
//	}
//
// CreateTar walks sourceRoot with filepath.WalkDir and writes regular
// files, empty directories, and symlinks to w as a tar stream. A directory
// root contributes its contents without an extra wrapper; a file or
// symlink root is emitted once under filepath.Base(sourceRoot). Symlinks
// are stored by target only and are never followed. File mode bits and
// modification times are preserved from os.Lstat. Every source descriptor
// is closed in the iteration that opened it. Devices, sockets, FIFOs, and
// every other unsupported node are hard errors.
//
// ExtractTar requires destRoot to be nonexistent or an empty real
// directory. It never merges into an existing tree. It accepts only
// TypeReg, TypeDir, and TypeSymlink entries; rejects NUL, backslashes,
// absolute paths, Windows drive forms, ".." segments, escaping targets,
// and writes through existing symlinks; and rejects non-portable or
// escaping symlink targets. Directory metadata is applied deepest-first
// after every child has been created.
//
// Each regular entry is copied with a ceiling of
// min(MaxEntrySize, remaining MaxTotalSize)+1. A violating file is removed
// before an error is returned. Zero-valued limits select finite defaults;
// negative limits are invalid. Context cancellation is checked between
// entries and during regular-file copies.
package archive

import "fmt"

// ExtractLimits bounds a single ExtractTar call. Every field's zero value
// falls back to the corresponding Default* constant; there is no way to
// request an unlimited extraction.
type ExtractLimits struct {
	// MaxEntries caps the number of tar entries (files, directories, and
	// symlinks combined) an archive may contain.
	MaxEntries int
	// MaxEntrySize caps the actual number of bytes copied for any single
	// regular-file entry, regardless of the size the tar header declares.
	MaxEntrySize int64
	// MaxTotalSize caps the cumulative number of actual bytes written
	// across all regular-file entries in the archive.
	MaxTotalSize int64
	// MaxPathDepth caps the number of path segments (after "." segments
	// are discarded) an entry name may contain.
	MaxPathDepth int
}

// Default limits applied to any ExtractLimits field left at its zero
// value.
const (
	DefaultMaxEntries   = 100_000
	DefaultMaxEntrySize = int64(4) << 30  // 4 GiB
	DefaultMaxTotalSize = int64(16) << 30 // 16 GiB
	DefaultMaxPathDepth = 64
)

func (l ExtractLimits) withDefaults() (ExtractLimits, error) {
	if l.MaxEntries < 0 || l.MaxEntrySize < 0 || l.MaxTotalSize < 0 || l.MaxPathDepth < 0 {
		return ExtractLimits{}, fmt.Errorf("archive: extraction limits must not be negative")
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxEntrySize == 0 {
		l.MaxEntrySize = DefaultMaxEntrySize
	}
	if l.MaxTotalSize == 0 {
		l.MaxTotalSize = DefaultMaxTotalSize
	}
	if l.MaxPathDepth == 0 {
		l.MaxPathDepth = DefaultMaxPathDepth
	}
	return l, nil
}
