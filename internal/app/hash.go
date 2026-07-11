package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
)

func (s *Service) Hash(ctx context.Context, req HashRequest, sink EventSink) ([]HashResult, error) {
	emit(sink, Event{Phase: PhaseValidating})
	if !hashing.Supported(req.Algorithm) {
		return nil, fmt.Errorf("app: unsupported hashing algorithm %q", req.Algorithm)
	}
	info, err := os.Lstat(req.InputPath)
	if err != nil {
		return nil, fmt.Errorf("app: inspect hash input %q: %w", req.InputPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("app: hash input symlinks are not followed")
	}
	if info.Mode().IsRegular() {
		result, err := hashFile(ctx, req.InputPath, filepath.Base(req.InputPath), req.Algorithm)
		if err != nil {
			return nil, err
		}
		emit(sink, Event{Phase: PhaseComplete, Current: 1, Total: 1, Detail: result.Path})
		return []HashResult{result}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("app: hash input %q is not a regular file or directory", req.InputPath)
	}

	var results []HashResult
	err = filepath.WalkDir(req.InputPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("app: walk hash input %q: %w", path, walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == req.InputPath || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("app: inspect hash entry %q: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("app: unsupported hash input node %q (mode %v)", path, info.Mode())
		}
		rel, err := filepath.Rel(req.InputPath, path)
		if err != nil {
			return fmt.Errorf("app: resolve hash result path %q: %w", path, err)
		}
		result, err := hashFile(ctx, path, filepath.ToSlash(rel), req.Algorithm)
		if err != nil {
			return err
		}
		results = append(results, result)
		emit(sink, Event{Phase: PhaseHashing, Current: int64(len(results)), Detail: result.Path})
		return nil
	})
	if err != nil {
		return nil, err
	}
	emit(sink, Event{Phase: PhaseComplete, Current: int64(len(results)), Total: int64(len(results))})
	return results, nil
}

func hashFile(ctx context.Context, path, resultPath string, algorithm hashing.ID) (HashResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return HashResult{}, fmt.Errorf("app: open hash input %q: %w", path, err)
	}
	digest, hashErr := hashing.Digest(ctx, file, algorithm)
	closeErr := file.Close()
	if hashErr != nil || closeErr != nil {
		return HashResult{}, errors.Join(hashErr, wrapError("app: close hash input", closeErr))
	}
	return HashResult{Path: resultPath, Digest: digest}, nil
}
