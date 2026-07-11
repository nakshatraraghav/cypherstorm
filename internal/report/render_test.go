package report_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/xuri/excelize/v2"
)

func emptySuccessesReport() *report.Report {
	return &report.Report{
		Failures: []report.Failure{
			{
				Combination: report.Combination{Codec: compress.CompressionGzip, Cipher: crypto.AES256GCM},
				Err:         errors.New("simulated cipher failure"),
			},
			{
				Combination: report.Combination{Codec: compress.CompressionLZ4, Cipher: crypto.XChaCha20Poly1305},
				Err:         errors.New("simulated codec failure"),
			},
		},
	}
}

func TestWriteTextReportZeroSuccessesNonzeroFailures(t *testing.T) {
	r := emptySuccessesReport()

	var buf bytes.Buffer
	if err := report.WriteTextReport(&buf, r); err != nil {
		t.Fatalf("WriteTextReport: unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "no successful combinations") {
		t.Fatalf("WriteTextReport output missing 'no successful combinations' message:\n%s", out)
	}
	if !strings.Contains(out, "simulated cipher failure") || !strings.Contains(out, "simulated codec failure") {
		t.Fatalf("WriteTextReport output missing failure details:\n%s", out)
	}
	if !strings.Contains(out, string(compress.CompressionGzip)) {
		t.Fatalf("WriteTextReport output missing failed combination codec:\n%s", out)
	}
}

func TestWriteTextReportDoesNotMutateSuccesses(t *testing.T) {
	r := &report.Report{
		Successes: []report.Success{
			{Combination: report.Combination{Codec: compress.CompressionLZMA, Cipher: crypto.AES256GCM}, CompressionRatio: 1.0},
			{Combination: report.Combination{Codec: compress.CompressionGzip, Cipher: crypto.AES256GCM}, CompressionRatio: 5.0},
		},
	}
	original := append([]report.Success(nil), r.Successes...)

	var buf bytes.Buffer
	if err := report.WriteTextReport(&buf, r); err != nil {
		t.Fatalf("WriteTextReport: unexpected error: %v", err)
	}

	for i := range original {
		if r.Successes[i] != original[i] {
			t.Fatalf("WriteTextReport mutated caller's Successes slice at index %d: got %+v, want %+v", i, r.Successes[i], original[i])
		}
	}
}

func TestRenderersRejectNilFailureErrors(t *testing.T) {
	r := &report.Report{Failures: []report.Failure{{
		Combination: report.Combination{Codec: compress.CompressionGzip, Cipher: crypto.AES256GCM},
	}}}

	var text bytes.Buffer
	if err := report.WriteTextReport(&text, r); err == nil {
		t.Fatal("WriteTextReport accepted a failure without an error")
	}
	if err := report.WriteExcelReport(filepath.Join(t.TempDir(), "invalid.xlsx"), r); err == nil {
		t.Fatal("WriteExcelReport accepted a failure without an error")
	}
}

func TestWriteExcelReportZeroSuccessesNonzeroFailures(t *testing.T) {
	r := emptySuccessesReport()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "benchmark.xlsx")

	if err := report.WriteExcelReport(path, r); err != nil {
		t.Fatalf("WriteExcelReport: unexpected error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("WriteExcelReport: output file missing: %v", err)
	}

	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("failed to reopen generated report: %v", err)
	}
	defer f.Close()

	for _, sheet := range []string{"Time Sorted Results", "Ratio Sorted Results", "Failures"} {
		if idx, err := f.GetSheetIndex(sheet); err != nil || idx == -1 {
			t.Fatalf("expected sheet %q in generated report (err=%v)", sheet, err)
		}
	}

	errCell, err := f.GetCellValue("Failures", "C2")
	if err != nil {
		t.Fatalf("GetCellValue: %v", err)
	}
	if errCell == "" {
		t.Fatal("Failures sheet row 2 column C (Error) is empty")
	}
}
