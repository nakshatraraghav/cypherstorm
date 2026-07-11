// Package report defines benchmark result models — successful and failed
// codec/cipher combinations — decoupled from the orchestration loop that
// runs them, plus text and XLSX renderers for the resulting Report.
//
// AllCombinations returns the deterministic cross product of
// compress.AllCodecs() and AllCipherIDs(), in fixed order, for callers
// driving a benchmark loop. Report.FastestSuccess and Report.BestRatioSuccess
// return (zero value, false) instead of panicking when a Report has no
// successful combinations — the regression fix for the previous
// timeResults[0]/ratioResults[0] panic when every combination fails.
//
// WriteTextReport renders a tabwriter-aligned report of successes (sorted
// by time and by compression ratio) and failures to an io.Writer.
// WriteExcelReport renders the same split to an XLSX workbook at a path,
// creating the parent directory as needed. Both render a report with zero
// successes and nonzero failures without panicking.
package report

import (
	"fmt"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
)

// Combination identifies one codec/cipher pair benchmarked together.
type Combination struct {
	Codec  compress.CompressionID
	Cipher crypto.CipherID
}

// Success records a benchmark combination that completed, along with its
// timing and size measurements.
type Success struct {
	Combination      Combination
	Duration         time.Duration
	OriginalSize     int64
	FinalSize        int64
	CompressionRatio float64
}

// Failure records a benchmark combination that failed, along with the
// error that caused the failure.
type Failure struct {
	Combination Combination
	Err         error
}

// Report is the full result of running a benchmark across combinations:
// every combination that succeeded and every combination that failed.
type Report struct {
	Successes []Success
	Failures  []Failure
}

func (r *Report) validate() error {
	if r == nil {
		return fmt.Errorf("report: report is nil")
	}
	for i, failure := range r.Failures {
		if failure.Err == nil {
			return fmt.Errorf("report: failure %d has no error", i)
		}
	}
	return nil
}

// FastestSuccess returns the Success with the smallest Duration. It returns
// (Success{}, false) instead of panicking when the Report has no
// successes, e.g. because every combination failed.
func (r *Report) FastestSuccess() (Success, bool) {
	if len(r.Successes) == 0 {
		return Success{}, false
	}

	fastest := r.Successes[0]
	for _, s := range r.Successes[1:] {
		if s.Duration < fastest.Duration {
			fastest = s
		}
	}
	return fastest, true
}

// BestRatioSuccess returns the Success with the highest CompressionRatio.
// It returns (Success{}, false) instead of panicking when the Report has
// no successes, e.g. because every combination failed.
func (r *Report) BestRatioSuccess() (Success, bool) {
	if len(r.Successes) == 0 {
		return Success{}, false
	}

	best := r.Successes[0]
	for _, s := range r.Successes[1:] {
		if s.CompressionRatio > best.CompressionRatio {
			best = s
		}
	}
	return best, true
}

// AllCombinations returns the deterministic cross product of
// compress.AllCodecs() and AllCipherIDs(), in fixed order: for each codec
// (gzip, zstd, lz4, bzip2, lzma) in turn, one Combination per cipher
// (aes-256-gcm, xchacha20poly1305).
func AllCombinations() []Combination {
	codecs := compress.AllCodecs()
	ciphers := crypto.AllCipherIDs()

	combinations := make([]Combination, 0, len(codecs)*len(ciphers))
	for _, codec := range codecs {
		for _, cipher := range ciphers {
			combinations = append(combinations, Combination{Codec: codec.ID(), Cipher: cipher})
		}
	}
	return combinations
}
