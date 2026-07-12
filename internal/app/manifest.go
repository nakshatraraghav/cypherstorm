package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
)

const maxManifestSize = 64 << 20
const maxManifestEntries = 1000000

type ManifestEntry struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"`
	Digest     string `json:"digest,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
}
type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	Root          string          `json:"root"`
	Entries       []ManifestEntry `json:"entries"`
}
type Change struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}
type CompareResult struct {
	Equal   bool     `json:"equal"`
	Changes []Change `json:"changes"`
}

func (s *Service) ManifestCreate(ctx context.Context, path, output string) (Manifest, error) {
	m, err := buildManifest(ctx, path)
	if err != nil {
		return Manifest{}, err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	data = append(data, '\n')
	if err = fsutil.PublishAtomic(output, false, func(f *os.File) error { _, e := f.Write(data); return e }); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func (s *Service) ManifestVerify(ctx context.Context, path, manifestPath string) (CompareResult, error) {
	expected, err := loadManifest(manifestPath)
	if err != nil {
		return CompareResult{}, err
	}
	actual, err := buildManifest(ctx, path)
	if err != nil {
		return CompareResult{}, err
	}
	return compareManifests(expected, actual), nil
}
func (s *Service) Compare(ctx context.Context, left, right string) (CompareResult, error) {
	a, err := buildManifest(ctx, left)
	if err != nil {
		return CompareResult{}, err
	}
	b, err := buildManifest(ctx, right)
	if err != nil {
		return CompareResult{}, err
	}
	return compareManifests(a, b), nil
}
func buildManifest(ctx context.Context, root string) (Manifest, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Manifest{}, err
	}
	var entries []ManifestEntry
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == abs {
			return nil
		}
		if len(entries) >= maxManifestEntries {
			return fmt.Errorf("manifest: entry limit exceeded")
		}
		rel, _ := filepath.Rel(abs, path)
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		e := ManifestEntry{Path: rel, Size: info.Size(), Mode: uint32(info.Mode().Perm())}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			e.Type = "symlink"
			e.LinkTarget, err = os.Readlink(path)
		case info.IsDir():
			e.Type = "directory"
		case info.Mode().IsRegular():
			e.Type = "file"
			before := info
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			h := sha256.New()
			_, copyErr := io.Copy(h, f)
			closeErr := f.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
			after, statErr := os.Lstat(path)
			if statErr != nil {
				return statErr
			}
			if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				return fmt.Errorf("manifest: source changed while hashing %q", rel)
			}
			e.Digest = hex.EncodeToString(h.Sum(nil))
		default:
			return fmt.Errorf("manifest: unsupported node %q", rel)
		}
		if err != nil {
			return err
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return Manifest{SchemaVersion: 1, Root: filepath.Base(abs), Entries: entries}, nil
}
func loadManifest(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestSize+1))
	if err != nil {
		return Manifest{}, err
	}
	if len(data) > maxManifestSize {
		return Manifest{}, fmt.Errorf("manifest: size limit exceeded")
	}
	var m Manifest
	dec := json.NewDecoder(bytesReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil {
		return Manifest{}, err
	}
	if m.SchemaVersion != 1 || len(m.Entries) > maxManifestEntries {
		return Manifest{}, fmt.Errorf("manifest: unsupported or excessive manifest")
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if seen[e.Path] {
			return Manifest{}, fmt.Errorf("manifest: duplicate path %q", e.Path)
		}
		seen[e.Path] = true
		if e.Type == "file" {
			digest, err := hex.DecodeString(e.Digest)
			if err != nil || len(digest) != sha256.Size {
				return Manifest{}, fmt.Errorf("manifest: malformed digest for %q", e.Path)
			}
		}
	}
	return m, nil
}

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }
func compareManifests(a, b Manifest) CompareResult {
	am, bm := map[string]ManifestEntry{}, map[string]ManifestEntry{}
	for _, e := range a.Entries {
		am[e.Path] = e
	}
	for _, e := range b.Entries {
		bm[e.Path] = e
	}
	keys := make([]string, 0, len(am)+len(bm))
	seen := map[string]bool{}
	for k := range am {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range bm {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	r := CompareResult{Equal: true}
	for _, k := range keys {
		x, xok := am[k]
		y, yok := bm[k]
		kind := ""
		switch {
		case !xok:
			kind = "added"
		case !yok:
			kind = "removed"
		case x.Type != y.Type:
			kind = "type-changed"
		case x.Digest != y.Digest || x.LinkTarget != y.LinkTarget || x.Size != y.Size || x.Mode != y.Mode:
			kind = "modified"
		}
		if kind != "" {
			r.Equal = false
			r.Changes = append(r.Changes, Change{Path: k, Kind: kind})
		}
	}
	return r
}
