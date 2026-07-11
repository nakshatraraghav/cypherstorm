package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nakshatraraghav/cypherstorm/internal/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/selection"
)

func (s *Service) Restore(ctx context.Context, req RestoreRequest, sink EventSink) (result RestoreResult, retErr error) {
	if req.Conflict == "" {
		req.Conflict = ConflictFail
	}
	if req.Overwrite {
		req.Conflict = ConflictOverwrite
	}
	switch req.Conflict {
	case ConflictFail, ConflictSkip, ConflictRename, ConflictOverwrite:
	default:
		return RestoreResult{}, fmt.Errorf("app: invalid conflict policy %q", req.Conflict)
	}
	if req.OutputPath == "" {
		return RestoreResult{}, fmt.Errorf("app: output path is required")
	}
	if err := fsutil.ValidateNoContainment(req.InputPath, req.OutputPath); err != nil {
		return RestoreResult{}, err
	}
	destInfo, destErr := os.Lstat(req.OutputPath)
	destExists := destErr == nil
	if destErr != nil && !errors.Is(destErr, fs.ErrNotExist) {
		return RestoreResult{}, destErr
	}
	if destExists && (!destInfo.IsDir() || destInfo.Mode()&os.ModeSymlink != 0) {
		return RestoreResult{}, fmt.Errorf("app: restore destination must be a non-symlink directory")
	}
	if destExists && req.Conflict == ConflictFail {
		return RestoreResult{}, fmt.Errorf("app: restore destination %q already exists", req.OutputPath)
	}
	parent := filepath.Dir(req.OutputPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return RestoreResult{}, err
	}
	emit(sink, Event{Phase: PhaseDecrypting})
	workspace, payload, codecID, err := s.decodeAuthenticated(ctx, req.InputPath, req.Credential, req.IdentityPaths, sink)
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { retErr = errors.Join(retErr, workspace.Close()) }()
	codec, err := compress.NewCodec(codecID)
	if err != nil {
		return RestoreResult{}, err
	}
	compressed, err := os.Open(payload)
	if err != nil {
		return RestoreResult{}, err
	}
	decoder, err := codec.NewReader(compressed)
	if err != nil {
		_ = compressed.Close()
		return RestoreResult{}, err
	}
	incoming, err := os.MkdirTemp(parent, ".cypherstorm-restore-*")
	if err != nil {
		return RestoreResult{}, err
	}
	published := false
	defer func() {
		if !published {
			retErr = errors.Join(retErr, os.RemoveAll(incoming))
		}
	}()
	selector := restoreEntrySelector(req)
	emit(sink, Event{Phase: PhaseDecompressing, Detail: string(codec.ID())})
	emit(sink, Event{Phase: PhaseExtracting, Detail: req.OutputPath})
	_, extractErr := archive.ExtractTarSelected(ctx, decoder, incoming, s.archiveLimits, selector)
	closeErr := errors.Join(decoder.Close(), compressed.Close())
	if extractErr != nil || closeErr != nil {
		return RestoreResult{}, errors.Join(extractErr, closeErr)
	}
	if !destExists {
		if err = fsutil.PublishDirectory(incoming, req.OutputPath); err != nil {
			return RestoreResult{}, err
		}
		published = true
		return RestoreResult{OutputPath: req.OutputPath}, nil
	}
	stage, err := os.MkdirTemp(parent, ".cypherstorm-merge-*")
	if err != nil {
		return RestoreResult{}, err
	}
	stagePublished := false
	defer func() {
		if !stagePublished {
			retErr = errors.Join(retErr, os.RemoveAll(stage))
		}
	}()
	if err = copyExistingTree(ctx, req.OutputPath, stage); err != nil {
		return RestoreResult{}, err
	}
	if err = mergeTrees(incoming, stage, req.Conflict); err != nil {
		return RestoreResult{}, err
	}
	if err = fsutil.ReplaceDirectory(stage, req.OutputPath); err != nil {
		return RestoreResult{}, err
	}
	stagePublished = true
	published = true
	_ = os.RemoveAll(incoming)
	return RestoreResult{OutputPath: req.OutputPath}, nil
}

func restoreEntrySelector(req RestoreRequest) archive.ExtractSelector {
	return func(entry archive.Entry) (bool, error) {
		selected := len(req.Includes) == 0 && len(req.Paths) == 0
		for _, p := range req.Paths {
			clean := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(p)), "/")
			if entry.Path == clean || strings.HasPrefix(entry.Path, clean+"/") {
				selected = true
			}
		}
		for _, p := range req.Includes {
			ok, err := selection.Match(p, entry.Path)
			if err != nil {
				return false, err
			}
			if ok {
				selected = true
			}
		}
		for _, p := range req.Excludes {
			ok, err := selection.Match(p, entry.Path)
			if err != nil {
				return false, err
			}
			if ok {
				return false, nil
			}
		}
		return selected, nil
	}
}

func copyExistingTree(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("app: conflict modes reject existing symlink %q", path)
		}
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("app: conflict modes reject special node %q", path)
		}
		if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := copyWithContext(ctx, out, in)
		return errors.Join(copyErr, in.Close(), out.Close())
	})
}

func mergeTrees(src, dst string, policy ConflictPolicy) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		from, to := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		srcInfo, err := os.Lstat(from)
		if err != nil {
			return err
		}
		dstInfo, err := os.Lstat(to)
		if errors.Is(err, fs.ErrNotExist) {
			if err = os.Rename(from, to); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if srcInfo.IsDir() && dstInfo.IsDir() && srcInfo.Mode()&os.ModeSymlink == 0 && dstInfo.Mode()&os.ModeSymlink == 0 {
			if err = mergeTrees(from, to, policy); err != nil {
				return err
			}
			_ = os.Remove(from)
			continue
		}
		switch policy {
		case ConflictSkip:
			continue
		case ConflictOverwrite:
			if err = os.RemoveAll(to); err != nil {
				return err
			}
			if err = os.Rename(from, to); err != nil {
				return err
			}
		case ConflictRename:
			renamed := ""
			for i := 1; i <= 10000; i++ {
				candidate := fmt.Sprintf("%s.restored-%d", to, i)
				if _, candidateErr := os.Lstat(candidate); errors.Is(candidateErr, fs.ErrNotExist) {
					renamed = candidate
					break
				}
			}
			if renamed == "" {
				return fmt.Errorf("app: cannot allocate deterministic rename for %q", to)
			}
			if err = os.Rename(from, renamed); err != nil {
				return err
			}
		default:
			return fmt.Errorf("app: unexpected conflict at %q", to)
		}
	}
	return nil
}
