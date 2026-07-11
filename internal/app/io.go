package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
)

func validateSource(path string) (os.FileInfo, error) {
	if path == "" {
		return nil, fmt.Errorf("app: input path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("app: inspect input %q: %w", path, err)
	}
	if info.IsDir() || info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return info, nil
	}
	return nil, fmt.Errorf("app: unsupported input node %q (mode %v)", path, info.Mode())
}

func prepareOutput(inputPath, outputPath string, overwrite bool) error {
	if outputPath == "" {
		return fmt.Errorf("app: output path is required")
	}
	if err := fsutil.ValidateNoContainment(inputPath, outputPath); err != nil {
		return err
	}
	if err := fsutil.ValidateOutputTarget(outputPath, overwrite); err != nil {
		return err
	}
	parent := filepath.Dir(outputPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("app: create output parent %q: %w", parent, err)
	}
	return nil
}

func buildCompressedArchive(ctx context.Context, sourcePath string, codec compress.Codec, ws *fsutil.Workspace, sink EventSink) (string, error) {
	compressed, err := ws.CreateFile("archive.compressed")
	if err != nil {
		return "", err
	}
	compressedPath := compressed.Name()

	writer, err := codec.NewWriter(compressed)
	if err != nil {
		_ = compressed.Close()
		return "", fmt.Errorf("app: create %s compressor: %w", codec.ID(), err)
	}

	emit(sink, Event{Phase: PhaseArchiving, Detail: sourcePath})
	emit(sink, Event{Phase: PhaseCompressing, Detail: string(codec.ID())})
	archiveErr := archive.CreateTar(ctx, sourcePath, writer)
	finalizeErr := writer.Close()
	if archiveErr != nil || finalizeErr != nil {
		_ = compressed.Close()
		return "", errors.Join(archiveErr, wrapError("app: finalize compressed archive", finalizeErr))
	}
	if err := compressed.Sync(); err != nil {
		_ = compressed.Close()
		return "", fmt.Errorf("app: sync compressed archive: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return "", fmt.Errorf("app: close compressed archive: %w", err)
	}
	return compressedPath, nil
}

func sourceSize(ctx context.Context, sourcePath string) (int64, error) {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return 0, fmt.Errorf("app: inspect source size: %w", err)
	}
	if info.Mode().IsRegular() {
		return info.Size(), nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, nil
	}

	var total int64
	err = filepath.WalkDir(sourcePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("app: calculate source size: %w", err)
	}
	return total, nil
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, appContextReader{ctx: ctx, reader: src})
}

type appContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r appContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
