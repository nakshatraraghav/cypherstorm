package pipeline

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/archiver"
	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
)

func DataProtectionPipeline(
	inputPath,
	outputPath string,
	password []byte,
	compressor compression.Compressor,
	encryptor encryption.Encryptor) error {

	tempArchivePath := filepath.Join(os.TempDir(), "archive.tar")
	tempCompressedPath := filepath.Join(os.TempDir(), "archive.tar.cmp")

	if err := archiver.CreateTarArchive(inputPath, tempArchivePath); err != nil {
		return fmt.Errorf("archive creation failed for source files: %w", err)
	}

	archiveFile, err := os.Open(tempArchivePath)
	if err != nil {
		return fmt.Errorf("could not open temporary archive file for compression: %w", err)
	}
	defer archiveFile.Close()

	compressedFile, err := os.Create(tempCompressedPath)
	if err != nil {
		return fmt.Errorf("failed to create file for compressed archive: %w", err)
	}
	defer compressedFile.Close()

	if err := compressor.Compress(archiveFile, compressedFile); err != nil {
		return fmt.Errorf("compression of archive file failed: %w", err)
	}

	if err := os.Remove(tempArchivePath); err != nil {
		fmt.Printf("WARNING: Could not delete temporary archive at %s: %v\n", tempArchivePath, err)
	}

	encryptedFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("could not create output file for encrypted data: %w", err)
	}
	defer encryptedFile.Close()

	compressedFileForEncryption, err := os.Open(tempCompressedPath)
	if err != nil {
		return fmt.Errorf("failed to open compressed file for encryption: %w", err)
	}
	defer compressedFileForEncryption.Close()

	if err := encryptor.Encrypt(compressedFileForEncryption, encryptedFile, password); err != nil {
		return fmt.Errorf("encryption of compressed file failed: %w", err)
	}

	fmt.Println("Files have been successfully archived, compressed, and encrypted.")

	if err := os.Remove(tempCompressedPath); err != nil {
		fmt.Printf("WARNING: Could not delete temporary compressed file at %s: %v\n", tempCompressedPath, err)
	}

	return nil
}
