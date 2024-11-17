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
)

type BenchmarkResult struct {
	CompressionAlgo  string
	EncryptionAlgo   string
	TimeTaken        time.Duration
	CompressionRatio float64
	OriginalSize     int64
	FinalSize        int64
}

func BenchmarkGenerator(inputPath string) error {

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

	sort.Slice(results, func(i, j int) bool {
		return results[i].TimeTaken < results[j].TimeTaken
	})

	f, err := os.Create("benchmark_report.log")
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	w := tabwriter.NewWriter(f, 0, 0, 3, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "Compression\tEncryption\tTime\tRatio\tOriginal Size\tFinal Size")
	fmt.Fprintln(w, "-----------\t----------\t----\t-----\t-------------\t----------")

	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2fx\t%d bytes\t%d bytes\n",
			r.CompressionAlgo,
			r.EncryptionAlgo,
			r.TimeTaken.Round(time.Millisecond),
			r.CompressionRatio,
			r.OriginalSize,
			r.FinalSize,
		)
	}
	w.Flush()

	fastest := results[0]
	fmt.Printf("\nFastest combination:\n")
	fmt.Printf("Compression: %s\n", fastest.CompressionAlgo)
	fmt.Printf("Encryption: %s\n", fastest.EncryptionAlgo)
	fmt.Printf("Time: %s\n", fastest.TimeTaken.Round(time.Millisecond))
	fmt.Printf("Compression ratio: %.2fx\n", fastest.CompressionRatio)

	return nil
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
