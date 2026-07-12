package report_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
)

func TestReportFastestAndBestRatioEmptyReturnsFalse(t *testing.T) {
	r := &report.Report{
		Failures: []report.Failure{
			{
				Combination: report.Combination{Codec: compress.CompressionGzip, Cipher: crypto.AES256GCM},
				Err:         errors.New("boom"),
			},
		},
	}

	if s, ok := r.FastestSuccess(); ok || s != (report.Success{}) {
		t.Fatalf("FastestSuccess() on empty successes = (%+v, %v), want (zero, false)", s, ok)
	}
	if s, ok := r.BestRatioSuccess(); ok || s != (report.Success{}) {
		t.Fatalf("BestRatioSuccess() on empty successes = (%+v, %v), want (zero, false)", s, ok)
	}
}

func TestReportFastestAndBestRatioPopulated(t *testing.T) {
	r := &report.Report{
		Successes: []report.Success{
			{
				Combination:      report.Combination{Codec: compress.CompressionGzip, Cipher: crypto.AES256GCM},
				Duration:         500 * time.Millisecond,
				OriginalSize:     1000,
				FinalSize:        600,
				CompressionRatio: 1.66,
			},
			{
				Combination:      report.Combination{Codec: compress.CompressionZstd, Cipher: crypto.XChaCha20Poly1305},
				Duration:         100 * time.Millisecond,
				OriginalSize:     1000,
				FinalSize:        300,
				CompressionRatio: 3.33,
			},
			{
				Combination:      report.Combination{Codec: compress.CompressionLZMA, Cipher: crypto.AES256GCM},
				Duration:         900 * time.Millisecond,
				OriginalSize:     1000,
				FinalSize:        500,
				CompressionRatio: 2.0,
			},
		},
	}

	fastest, ok := r.FastestSuccess()
	if !ok {
		t.Fatal("FastestSuccess(): expected ok=true")
	}
	if fastest.Combination.Codec != compress.CompressionZstd {
		t.Fatalf("FastestSuccess() codec = %q, want %q", fastest.Combination.Codec, compress.CompressionZstd)
	}

	best, ok := r.BestRatioSuccess()
	if !ok {
		t.Fatal("BestRatioSuccess(): expected ok=true")
	}
	if best.Combination.Codec != compress.CompressionZstd {
		t.Fatalf("BestRatioSuccess() codec = %q, want %q", best.Combination.Codec, compress.CompressionZstd)
	}
}

func TestAllCombinationsDeterministicCrossProduct(t *testing.T) {
	combos := report.AllCombinations()

	wantCodecs := len(compress.AllCodecs())
	wantCiphers := len(crypto.AllCipherIDs())
	if len(combos) != wantCodecs*wantCiphers {
		t.Fatalf("AllCombinations() returned %d combinations, want %d", len(combos), wantCodecs*wantCiphers)
	}

	// Deterministic and stable across calls.
	again := report.AllCombinations()
	for i := range combos {
		if combos[i] != again[i] {
			t.Fatalf("AllCombinations() not deterministic at index %d: %+v vs %+v", i, combos[i], again[i])
		}
	}

	// Fixed order: codec-major, matching compress.AllCodecs() order.
	codecs := compress.AllCodecs()
	ciphers := crypto.AllCipherIDs()
	idx := 0
	for _, codec := range codecs {
		for _, cipher := range ciphers {
			want := report.Combination{Codec: codec.ID(), Cipher: cipher}
			if combos[idx] != want {
				t.Fatalf("AllCombinations()[%d] = %+v, want %+v", idx, combos[idx], want)
			}
			idx++
		}
	}
}
