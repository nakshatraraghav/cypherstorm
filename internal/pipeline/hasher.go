package pipeline

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
)

func CalculateHashPipeline(inputPath string, hasher hashing.Hasher) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to get the file info: %v", err)
	}

	if !info.IsDir() {
		hash, err := hashfn(inputPath, hasher)
		if err != nil {
			return err
		}

		fmt.Printf("%s: %s\n", inputPath, hash)

		return nil
	} else {

		return filepath.Walk(inputPath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				hash, err := hashfn(path, hasher)
				if err != nil {
					return err
				}
				fmt.Printf("%s: %s\n\n", path, hash)
			}
			return nil
		})
	}
}

func hashfn(filePath string, hasher hashing.Hasher) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash, err := hasher.Hash(file)
	if err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hash, nil
}
