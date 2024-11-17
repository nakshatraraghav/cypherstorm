package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
	"github.com/nakshatraraghav/cypherstorm/internal/keyman"
	"github.com/xuri/excelize/v2"
)

type BenchmarkResult struct {
	CompressionAlgo  string
	EncryptionAlgo   string
	TimeTaken        time.Duration
	CompressionRatio float64
	OriginalSize     int64
	FinalSize        int64
}

func BenchmarkGenerator(inputPath, outputPath string) error {
	fmt.Printf("starting the benchmark process\n\n")
	var results []BenchmarkResult

	km := keyman.NewKeyManager(32, 16)
	password, err := km.DeriveKeyFromPassword("benchmark")
	if err != nil {
		return err
	}

	encryptors := map[string]encryption.Encryptor{
		"aes-256-gcm":       encryption.NewAesGcmEncryptor(),
		"xchacha20poly1305": encryption.NewXChaCha20Poly1305Encryptor(),
	}

	compressors := map[string]compression.Compressor{
		"gzip":  compression.NewGzipCompressor(),
		"bzip2": compression.NewBzipCompressor(),
		"lz4":   compression.NewLz4Compressor(),
		"lzma":  compression.NewLzmaCompressor(),
		"zstd":  compression.NewZstdCompressor(),
	}

	tmpDir, err := os.MkdirTemp("", "cypherstorm-benchmark")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	originalSize, err := getDirSize(inputPath)
	if err != nil {
		return fmt.Errorf("failed to get original size: %w", err)
	}

	for encName, enc := range encryptors {
		for cmpName, cmp := range compressors {
			outputPath := filepath.Join(tmpDir, fmt.Sprintf("benchmark_%s_%s", encName, cmpName))
			fmt.Printf("starting processing for %s and %s\n", cmpName, encName)

			start := time.Now()
			err := DataProtectionPipeline(
				inputPath,
				outputPath,
				password,
				cmp,
				enc,
			)
			if err != nil {
				fmt.Printf("Warning: combination %s-%s failed: %v\n", cmpName, encName, err)
				continue
			}
			fmt.Printf("\n")

			duration := time.Since(start)

			finalSize, err := os.Stat(outputPath)
			if err != nil {
				fmt.Printf("Warning: couldn't get size for %s-%s: %v\n", cmpName, encName, err)
				continue
			}

			compressionRatio := float64(originalSize) / float64(finalSize.Size())

			results = append(results, BenchmarkResult{
				CompressionAlgo:  cmpName,
				EncryptionAlgo:   encName,
				TimeTaken:        duration,
				CompressionRatio: compressionRatio,
				OriginalSize:     originalSize,
				FinalSize:        finalSize.Size(),
			})

			err = os.Remove(outputPath)
			if err != nil {
				fmt.Printf("WARN: Failed to delete file: %s", outputPath)
			}
		}
	}

	timeResults := make([]BenchmarkResult, len(results))
	ratioResults := make([]BenchmarkResult, len(results))

	copy(timeResults, results)
	copy(ratioResults, results)

	sort.Slice(timeResults, func(i, j int) bool {
		return timeResults[i].TimeTaken < timeResults[j].TimeTaken
	})

	sort.Slice(ratioResults, func(i, j int) bool {
		return ratioResults[i].CompressionRatio > ratioResults[j].CompressionRatio
	})

	if err := generateLogReport(outputPath, timeResults, ratioResults); err != nil {
		return fmt.Errorf("failed to generate log report: %w", err)
	}

	if err := generateExcelReport(outputPath, timeResults, ratioResults); err != nil {
		return fmt.Errorf("failed to generate Excel report: %w", err)
	}

	fastest := timeResults[0]
	fmt.Printf("\nFastest combination:\n")
	fmt.Printf("Compression: %s\n", fastest.CompressionAlgo)
	fmt.Printf("Encryption: %s\n", fastest.EncryptionAlgo)
	fmt.Printf("Time: %s\n", fastest.TimeTaken.Round(time.Millisecond))
	fmt.Printf("Compression ratio: %.2fx\n", fastest.CompressionRatio)

	bestCompression := ratioResults[0]
	fmt.Printf("\nBest compression:\n")
	fmt.Printf("Compression: %s\n", bestCompression.CompressionAlgo)
	fmt.Printf("Encryption: %s\n", bestCompression.EncryptionAlgo)
	fmt.Printf("Time: %s\n", bestCompression.TimeTaken.Round(time.Millisecond))
	fmt.Printf("Compression ratio: %.2fx\n", bestCompression.CompressionRatio)

	return nil
}

func generateLogReport(outputPath string, timeResults, ratioResults []BenchmarkResult) error {
	logFilePath := filepath.Join(outputPath, "benchmark.log")

	f, err := os.Create(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	w := tabwriter.NewWriter(f, 0, 0, 3, ' ', tabwriter.TabIndent)

	fmt.Fprintln(w, "Results Sorted by Time:")
	fmt.Fprintln(w, "=====================")
	fmt.Fprintln(w, "Compression\tEncryption\tTime\tRatio\tOriginal Size\tFinal Size")
	fmt.Fprintln(w, "-----------\t----------\t----\t-----\t-------------\t----------")
	for _, r := range timeResults {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2fx\t%d bytes\t%d bytes\n",
			r.CompressionAlgo,
			r.EncryptionAlgo,
			r.TimeTaken.Round(time.Millisecond),
			r.CompressionRatio,
			r.OriginalSize,
			r.FinalSize,
		)
	}

	fmt.Fprintln(w, "\nResults Sorted by Compression Ratio:")
	fmt.Fprintln(w, "==================================")
	fmt.Fprintln(w, "Compression\tEncryption\tTime\tRatio\tOriginal Size\tFinal Size")
	fmt.Fprintln(w, "-----------\t----------\t----\t-----\t-------------\t----------")
	for _, r := range ratioResults {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2fx\t%d bytes\t%d bytes\n",
			r.CompressionAlgo,
			r.EncryptionAlgo,
			r.TimeTaken.Round(time.Millisecond),
			r.CompressionRatio,
			r.OriginalSize,
			r.FinalSize,
		)
	}

	return w.Flush()
}

func generateExcelReport(outputPath string, timeResults, ratioResults []BenchmarkResult) error {
	excelFilePath := filepath.Join(outputPath, "benchmark.xlsx")
	f := excelize.NewFile()

	timeSheet := "Time Sorted Results"
	f.SetSheetName("Sheet1", timeSheet)

	headers := []string{"Compression", "Encryption", "Time", "Ratio", "Original Size", "Final Size"}
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(timeSheet, cell, header)
	}

	for i, r := range timeResults {
		row := i + 2
		f.SetCellValue(timeSheet, fmt.Sprintf("A%d", row), r.CompressionAlgo)
		f.SetCellValue(timeSheet, fmt.Sprintf("B%d", row), r.EncryptionAlgo)
		f.SetCellValue(timeSheet, fmt.Sprintf("C%d", row), r.TimeTaken.Round(time.Millisecond).String())
		f.SetCellValue(timeSheet, fmt.Sprintf("D%d", row), fmt.Sprintf("%.2fx", r.CompressionRatio))
		f.SetCellValue(timeSheet, fmt.Sprintf("E%d", row), r.OriginalSize)
		f.SetCellValue(timeSheet, fmt.Sprintf("F%d", row), r.FinalSize)
	}

	ratioSheet := "Ratio Sorted Results"
	f.NewSheet(ratioSheet)

	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(ratioSheet, cell, header)
	}

	for i, r := range ratioResults {
		row := i + 2
		f.SetCellValue(ratioSheet, fmt.Sprintf("A%d", row), r.CompressionAlgo)
		f.SetCellValue(ratioSheet, fmt.Sprintf("B%d", row), r.EncryptionAlgo)
		f.SetCellValue(ratioSheet, fmt.Sprintf("C%d", row), r.TimeTaken.Round(time.Millisecond).String())
		f.SetCellValue(ratioSheet, fmt.Sprintf("D%d", row), fmt.Sprintf("%.2fx", r.CompressionRatio))
		f.SetCellValue(ratioSheet, fmt.Sprintf("E%d", row), r.OriginalSize)
		f.SetCellValue(ratioSheet, fmt.Sprintf("F%d", row), r.FinalSize)
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#CCCCCC"}, Pattern: 1},
	})
	f.SetRowStyle(timeSheet, 1, 1, style)
	f.SetRowStyle(ratioSheet, 1, 1, style)

	for _, sheet := range []string{timeSheet, ratioSheet} {
		for i := 1; i <= 6; i++ {
			colName, _ := excelize.ColumnNumberToName(i)
			f.SetColWidth(sheet, colName, colName, 15)
		}
	}

	return f.SaveAs(excelFilePath)
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}
