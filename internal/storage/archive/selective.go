package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ExtractSelector func(Entry) (bool, error)

// ExtractTarSelected validates every entry and writes only selected entries.
func ExtractTarSelected(ctx context.Context, r io.Reader, destRoot string, limits ExtractLimits, selectEntry ExtractSelector) (ScanSummary, error) {
	limits, err := limits.withDefaults()
	if err != nil {
		return ScanSummary{}, err
	}
	root, err := filepath.Abs(destRoot)
	if err != nil {
		return ScanSummary{}, err
	}
	if err = prepareDestination(root); err != nil {
		return ScanSummary{}, err
	}
	tr := tar.NewReader(r)
	seen := map[string]EntryType{}
	var summary ScanSummary
	selected := 0
	for {
		if err = ctx.Err(); err != nil {
			return ScanSummary{}, err
		}
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			if selected == 0 {
				return ScanSummary{}, fmt.Errorf("archive: selection is empty")
			}
			return summary, nil
		}
		if e != nil {
			return ScanSummary{}, fmt.Errorf("archive: read tar header: %w", e)
		}
		summary.Entries++
		if summary.Entries > limits.MaxEntries {
			return ScanSummary{}, fmt.Errorf("archive: extraction exceeds MaxEntries limit (%d)", limits.MaxEntries)
		}
		parts, e := validateEntryName(h.Name)
		if e != nil {
			return ScanSummary{}, e
		}
		if len(parts) > limits.MaxPathDepth {
			return ScanSummary{}, fmt.Errorf("archive: entry %q exceeds path depth limit", h.Name)
		}
		name := strings.Join(parts, "/")
		if _, ok := seen[name]; ok {
			return ScanSummary{}, fmt.Errorf("archive: duplicate entry path %q", name)
		}
		entry := Entry{Path: name, Mode: os.FileMode(h.Mode).Perm(), ModTime: h.ModTime}
		switch h.Typeflag {
		case tar.TypeReg:
			entry.Type, entry.Size = EntryFile, h.Size
			if h.Size < 0 || h.Size > limits.MaxEntrySize {
				return ScanSummary{}, fmt.Errorf("archive: entry %q exceeds size limit", name)
			}
			if summary.Bytes > limits.MaxTotalSize-h.Size {
				return ScanSummary{}, fmt.Errorf("archive: extraction exceeds total size limit")
			}
			summary.Bytes += h.Size
			summary.Files++
		case tar.TypeDir:
			entry.Type = EntryDir
			summary.Dirs++
		case tar.TypeSymlink:
			entry.Type, entry.LinkTarget = EntrySymlink, h.Linkname
			summary.Links++
			if e = validatePortableSymlink(name, h.Linkname); e != nil {
				return ScanSummary{}, e
			}
		default:
			return ScanSummary{}, fmt.Errorf("archive: unsupported tar entry type %v for %q", h.Typeflag, name)
		}
		seen[name] = entry.Type
		include := true
		if selectEntry != nil {
			include, e = selectEntry(entry)
			if e != nil {
				return ScanSummary{}, e
			}
		}
		target, e := secureJoin(root, parts)
		if e != nil {
			return ScanSummary{}, e
		}
		if !include {
			if entry.Type == EntryFile {
				if _, e = io.CopyN(io.Discard, contextReader{ctx: ctx, reader: tr}, h.Size); e != nil {
					return ScanSummary{}, fmt.Errorf("archive: validate unselected entry %q: %w", name, e)
				}
			}
			continue
		}
		selected++
		switch entry.Type {
		case EntryDir:
			if e = extractDir(target); e != nil {
				return ScanSummary{}, e
			}
		case EntrySymlink:
			if e = extractSymlink(target, h, root); e != nil {
				return ScanSummary{}, e
			}
		case EntryFile:
			if e = os.MkdirAll(filepath.Dir(target), 0o700); e != nil {
				return ScanSummary{}, e
			}
			if _, e = extractRegularFile(ctx, tr, target, h, h.Size); e != nil {
				return ScanSummary{}, e
			}
		}
	}
}
