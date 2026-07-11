package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/xuri/excelize/v2"
)

// WriteExcelReport renders r as an XLSX workbook saved at path: a "Time
// Sorted Results" sheet, a "Ratio Sorted Results" sheet (headered but
// otherwise empty when r has no successes), and a "Failures" sheet listing
// each failed combination and its error. It creates path's parent
// directory if missing and returns excelize save/style errors instead of
// ignoring them.
func WriteExcelReport(path string, r *Report) (err error) {
	if err := r.validate(); err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("report: failed to create report directory %q: %w", dir, err)
		}
	}

	f := excelize.NewFile()
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("report: close excel workbook: %w", closeErr))
		}
	}()

	byTime := append([]Success(nil), r.Successes...)
	sort.SliceStable(byTime, func(i, j int) bool {
		return byTime[i].Duration < byTime[j].Duration
	})

	byRatio := append([]Success(nil), r.Successes...)
	sort.SliceStable(byRatio, func(i, j int) bool {
		return byRatio[i].CompressionRatio > byRatio[j].CompressionRatio
	})

	const timeSheet = "Time Sorted Results"
	if err := f.SetSheetName("Sheet1", timeSheet); err != nil {
		return fmt.Errorf("report: failed to name sheet %q: %w", timeSheet, err)
	}
	if err := writeSuccessSheet(f, timeSheet, byTime); err != nil {
		return err
	}

	const ratioSheet = "Ratio Sorted Results"
	if _, err := f.NewSheet(ratioSheet); err != nil {
		return fmt.Errorf("report: failed to create sheet %q: %w", ratioSheet, err)
	}
	if err := writeSuccessSheet(f, ratioSheet, byRatio); err != nil {
		return err
	}

	const failuresSheet = "Failures"
	if _, err := f.NewSheet(failuresSheet); err != nil {
		return fmt.Errorf("report: failed to create sheet %q: %w", failuresSheet, err)
	}
	if err := writeFailuresSheet(f, failuresSheet, r.Failures); err != nil {
		return err
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#CCCCCC"}, Pattern: 1},
	})
	if err != nil {
		return fmt.Errorf("report: failed to create header style: %w", err)
	}
	for _, sheet := range []string{timeSheet, ratioSheet, failuresSheet} {
		if err := f.SetRowStyle(sheet, 1, 1, headerStyle); err != nil {
			return fmt.Errorf("report: failed to style sheet %q: %w", sheet, err)
		}
	}

	if err := f.SaveAs(path); err != nil {
		return fmt.Errorf("report: failed to save excel report to %q: %w", path, err)
	}
	return nil
}

func writeSuccessSheet(f *excelize.File, sheet string, results []Success) error {
	headers := []string{"Compression", "Cipher", "Time", "Ratio", "Original Size", "Final Size"}
	for i, header := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		if err != nil {
			return fmt.Errorf("report: calculate header cell for sheet %q: %w", sheet, err)
		}
		if err := f.SetCellValue(sheet, cell, header); err != nil {
			return fmt.Errorf("report: write header cell %s on sheet %q: %w", cell, sheet, err)
		}
	}

	for i, s := range results {
		row := i + 2
		values := []any{
			string(s.Combination.Codec),
			string(s.Combination.Cipher),
			s.Duration.Round(time.Millisecond).String(),
			fmt.Sprintf("%.2fx", s.CompressionRatio),
			s.OriginalSize,
			s.FinalSize,
		}
		for column, value := range values {
			cell, err := excelize.CoordinatesToCellName(column+1, row)
			if err != nil {
				return fmt.Errorf("report: calculate result cell for sheet %q: %w", sheet, err)
			}
			if err := f.SetCellValue(sheet, cell, value); err != nil {
				return fmt.Errorf("report: write result cell %s on sheet %q: %w", cell, sheet, err)
			}
		}
	}

	for i := 1; i <= len(headers); i++ {
		colName, err := excelize.ColumnNumberToName(i)
		if err != nil {
			return fmt.Errorf("report: calculate column name for sheet %q: %w", sheet, err)
		}
		if err := f.SetColWidth(sheet, colName, colName, 15); err != nil {
			return fmt.Errorf("report: set column width on sheet %q: %w", sheet, err)
		}
	}
	return nil
}

func writeFailuresSheet(f *excelize.File, sheet string, failures []Failure) error {
	headers := []string{"Compression", "Cipher", "Error"}
	for i, header := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		if err != nil {
			return fmt.Errorf("report: calculate failure header cell for sheet %q: %w", sheet, err)
		}
		if err := f.SetCellValue(sheet, cell, header); err != nil {
			return fmt.Errorf("report: write failure header cell %s on sheet %q: %w", cell, sheet, err)
		}
	}

	for i, failure := range failures {
		row := i + 2
		values := []any{
			string(failure.Combination.Codec),
			string(failure.Combination.Cipher),
			failure.Err.Error(),
		}
		for column, value := range values {
			cell, err := excelize.CoordinatesToCellName(column+1, row)
			if err != nil {
				return fmt.Errorf("report: calculate failure cell for sheet %q: %w", sheet, err)
			}
			if err := f.SetCellValue(sheet, cell, value); err != nil {
				return fmt.Errorf("report: write failure cell %s on sheet %q: %w", cell, sheet, err)
			}
		}
	}

	for i := 1; i <= len(headers); i++ {
		colName, err := excelize.ColumnNumberToName(i)
		if err != nil {
			return fmt.Errorf("report: calculate failure column name for sheet %q: %w", sheet, err)
		}
		if err := f.SetColWidth(sheet, colName, colName, 30); err != nil {
			return fmt.Errorf("report: set failure column width on sheet %q: %w", sheet, err)
		}
	}
	return nil
}
