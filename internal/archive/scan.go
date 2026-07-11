package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	pathpkg "path"
	"strings"
	"time"
)

type EntryType string

const (
	EntryFile    EntryType = "file"
	EntryDir     EntryType = "directory"
	EntrySymlink EntryType = "symlink"
)

type Entry struct {
	Path       string      `json:"path"`
	Type       EntryType   `json:"type"`
	Size       int64       `json:"size"`
	Mode       fs.FileMode `json:"mode"`
	ModTime    time.Time   `json:"mod_time"`
	LinkTarget string      `json:"link_target,omitempty"`
}

type ScanOptions struct {
	Limits ExtractLimits
	Visit  func(Entry) error
}

type ScanSummary struct {
	Entries int   `json:"entries"`
	Files   int   `json:"files"`
	Dirs    int   `json:"directories"`
	Links   int   `json:"symlinks"`
	Bytes   int64 `json:"bytes"`
}

// ScanTar validates and consumes a complete tar stream without writing files.
// It applies the same path, type, symlink and resource policy as extraction.
func ScanTar(ctx context.Context, r io.Reader, options ScanOptions) (ScanSummary, error) {
	limits, err := options.Limits.withDefaults()
	if err != nil {
		return ScanSummary{}, err
	}
	tr := tar.NewReader(r)
	seen := make(map[string]EntryType)
	var summary ScanSummary
	for {
		if err := ctx.Err(); err != nil {
			return ScanSummary{}, fmt.Errorf("archive: scan cancelled: %w", err)
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return summary, nil
		}
		if err != nil {
			return ScanSummary{}, fmt.Errorf("archive: read tar header: %w", err)
		}
		summary.Entries++
		if summary.Entries > limits.MaxEntries {
			return ScanSummary{}, fmt.Errorf("archive: scan exceeds MaxEntries limit (%d)", limits.MaxEntries)
		}
		segments, err := validateEntryName(h.Name)
		if err != nil {
			return ScanSummary{}, err
		}
		if len(segments) > limits.MaxPathDepth {
			return ScanSummary{}, fmt.Errorf("archive: entry %q exceeds MaxPathDepth limit (%d)", h.Name, limits.MaxPathDepth)
		}
		name := strings.Join(segments, "/")
		if _, exists := seen[name]; exists {
			return ScanSummary{}, fmt.Errorf("archive: duplicate entry path %q", name)
		}
		for parent := pathpkg.Dir(name); parent != "."; parent = pathpkg.Dir(parent) {
			if typ, exists := seen[parent]; exists && typ != EntryDir {
				return ScanSummary{}, fmt.Errorf("archive: entry %q conflicts with non-directory parent %q", name, parent)
			}
		}
		var entry Entry
		entry.Path, entry.Mode, entry.ModTime = name, fs.FileMode(h.Mode).Perm(), h.ModTime
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > limits.MaxEntrySize {
				return ScanSummary{}, fmt.Errorf("archive: entry %q exceeds MaxEntrySize limit (%d bytes)", name, limits.MaxEntrySize)
			}
			if summary.Bytes > limits.MaxTotalSize-h.Size {
				return ScanSummary{}, fmt.Errorf("archive: scan exceeds MaxTotalSize limit (%d bytes)", limits.MaxTotalSize)
			}
			entry.Type, entry.Size = EntryFile, h.Size
			summary.Files++
			summary.Bytes += h.Size
			if _, err := io.CopyN(io.Discard, contextReader{ctx: ctx, reader: tr}, h.Size); err != nil {
				return ScanSummary{}, fmt.Errorf("archive: read entry %q payload: %w", name, err)
			}
		case tar.TypeDir:
			entry.Type = EntryDir
			summary.Dirs++
		case tar.TypeSymlink:
			entry.Type, entry.LinkTarget = EntrySymlink, h.Linkname
			if err := validatePortableSymlink(name, h.Linkname); err != nil {
				return ScanSummary{}, err
			}
			summary.Links++
		default:
			return ScanSummary{}, fmt.Errorf("archive: unsupported tar entry type %v for %q", h.Typeflag, name)
		}
		seen[name] = entry.Type
		if options.Visit != nil {
			if err := options.Visit(entry); err != nil {
				return ScanSummary{}, err
			}
		}
	}
}

func validatePortableSymlink(name, target string) error {
	if target == "" || strings.ContainsRune(target, '\x00') || strings.Contains(target, `\`) || pathpkg.IsAbs(target) || isWindowsDrivePath(target) {
		return fmt.Errorf("archive: symlink %q has unsafe target %q", name, target)
	}
	resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(name), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("archive: symlink %q target escapes archive root", name)
	}
	return nil
}
