package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
)

var ErrNoBenchmarkSuccess = errors.New("app: every benchmark combination failed")

type benchmarkRunner func(context.Context, string, report.Combination) (int64, error)

func (s *Service) Benchmark(ctx context.Context, req BenchmarkRequest, sink EventSink) (report.Report, error) {
	emit(sink, Event{Phase: PhaseValidating})
	if _, err := validateSource(req.InputPath); err != nil {
		return report.Report{}, err
	}
	if req.OutputPath != "" {
		if err := prepareOutput(req.InputPath, req.OutputPath, false); err != nil {
			return report.Report{}, err
		}
	}
	originalSize, err := sourceSize(ctx, req.InputPath)
	if err != nil {
		return report.Report{}, err
	}

	combinations := report.AllCombinations()
	result := report.Report{
		Successes: make([]report.Success, 0, len(combinations)),
		Failures:  make([]report.Failure, 0),
	}
	runner := benchmarkRunner(s.runBenchmarkCombination)
	if s.benchmarkRunner != nil {
		runner = s.benchmarkRunner
	}
	for index, combination := range combinations {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		emit(sink, Event{
			Phase:   PhaseBenchmarking,
			Current: int64(index),
			Total:   int64(len(combinations)),
			Detail:  fmt.Sprintf("%s + %s", combination.Codec, combination.Cipher),
		})
		started := s.now()
		finalSize, runErr := runner(ctx, req.InputPath, combination)
		duration := s.now().Sub(started)
		if runErr != nil {
			result.Failures = append(result.Failures, report.Failure{Combination: combination, Err: runErr})
			continue
		}
		ratio := float64(0)
		if finalSize > 0 {
			ratio = float64(originalSize) / float64(finalSize)
		}
		result.Successes = append(result.Successes, report.Success{
			Combination:      combination,
			Duration:         duration,
			OriginalSize:     originalSize,
			FinalSize:        finalSize,
			CompressionRatio: ratio,
		})
	}

	var reportErr error
	if req.OutputPath != "" {
		reportErr = writeBenchmarkReport(ctx, req.OutputPath, &result)
	}
	if len(result.Successes) == 0 {
		return result, errors.Join(ErrNoBenchmarkSuccess, reportErr)
	}
	if reportErr != nil {
		return result, reportErr
	}
	emit(sink, Event{Phase: PhaseComplete, Current: int64(len(combinations)), Total: int64(len(combinations)), Detail: req.OutputPath})
	return result, nil
}

func (s *Service) runBenchmarkCombination(ctx context.Context, inputPath string, combination report.Combination) (int64, error) {
	workspace, err := fsutil.NewWorkspace()
	if err != nil {
		return 0, err
	}
	codec, err := compress.NewCodec(combination.Codec)
	if err != nil {
		_ = workspace.Close()
		return 0, err
	}
	compressedPath, runErr := buildCompressedArchive(ctx, inputPath, codec, workspace, nil)
	if runErr != nil {
		return 0, errors.Join(runErr, workspace.Close())
	}
	compressed, err := os.Open(compressedPath)
	if err != nil {
		return 0, errors.Join(err, workspace.Close())
	}
	wireCodec, err := wireCodecID(combination.Codec)
	if err != nil {
		_ = compressed.Close()
		return 0, errors.Join(err, workspace.Close())
	}
	counter := &countingWriter{writer: io.Discard}
	runErr = crypto.Encrypt(ctx, compressed, counter, crypto.EncryptOptions{
		Credential: kdf.Credential{Kind: kdf.SourceRaw, RawKey: make([]byte, kdf.MasterKeySize)},
		CipherID:   combination.Cipher,
		CodecID:    wireCodec,
		Argon2:     s.argon2,
		RecordSize: s.recordSize,
	})
	closeErr := compressed.Close()
	workspaceErr := workspace.Close()
	if runErr != nil || closeErr != nil || workspaceErr != nil {
		return 0, errors.Join(runErr, wrapError("app: close benchmark input", closeErr), workspaceErr)
	}
	return counter.written, nil
}

func writeBenchmarkReport(ctx context.Context, outputPath string, benchmark *report.Report) error {
	workspace, err := fsutil.NewWorkspace()
	if err != nil {
		return err
	}
	temporaryReport := filepath.Join(workspace.Root(), "benchmark.xlsx")
	if err := report.WriteExcelReport(temporaryReport, benchmark); err != nil {
		return errors.Join(err, workspace.Close())
	}
	input, err := os.Open(temporaryReport)
	if err != nil {
		return errors.Join(err, workspace.Close())
	}
	publishErr := fsutil.PublishAtomic(outputPath, false, func(output *os.File) error {
		_, err := copyWithContext(ctx, output, input)
		return err
	})
	closeErr := input.Close()
	workspaceErr := workspace.Close()
	return errors.Join(publishErr, wrapError("app: close benchmark report", closeErr), workspaceErr)
}

type countingWriter struct {
	writer  io.Writer
	written int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.written += int64(n)
	return n, err
}
