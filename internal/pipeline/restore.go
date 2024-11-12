package pipeline

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/archiver"
	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
)

func DataRecoveryPipeline(
	inputPath,
	outputPath string,
	password []byte,
	compressor compression.Compressor,
	encryptor encryption.Encryptor) error {

	tempDecryptedPath := filepath.Join(os.TempDir(), "decrypted.tar.cmp")
	tempDecompressedPath := filepath.Join(os.TempDir(), "decrypted.tar")

	encryptedFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer encryptedFile.Close()

	decryptedFile, err := os.Create(tempDecryptedPath)
	if err != nil {
		return fmt.Errorf("could not create output file for decrypted data: %w", err)
	}
	defer decryptedFile.Close()

	if err := encryptor.Decrypt(encryptedFile, decryptedFile, password); err != nil {
		return fmt.Errorf("decryption of encrypted file failed: %w", err)
	}

	decryptedFileForDecompression, err := os.Open(tempDecryptedPath)
	if err != nil {
		return fmt.Errorf("failed to reopen decrypted file for decompression: %w", err)
	}
	defer decryptedFileForDecompression.Close()

	decompressedFile, err := os.Create(tempDecompressedPath)
	if err != nil {
		return fmt.Errorf("could not create output file for decompressed archive: %w", err)
	}
	defer decompressedFile.Close()

	if err := compressor.Decompress(decryptedFileForDecompression, decompressedFile); err != nil {
		return fmt.Errorf("decompression of decrypted archive failed: %w", err)
	}

	if err := os.Remove(tempDecryptedPath); err != nil {
		fmt.Printf("WARNING: Could not delete temporary decrypted file at %s: %v\n", tempDecryptedPath, err)
	}

	if err := archiver.ExtractTarArchive(tempDecompressedPath, outputPath); err != nil {
		return fmt.Errorf("extraction of decompressed archive failed: %w", err)
	}

	fmt.Println("Files have been successfully decrypted, decompressed, and restored.")

	if err := os.Remove(tempDecompressedPath); err != nil {
		fmt.Printf("WARNING: Could not delete temporary decompressed file at %s: %v\n", tempDecompressedPath, err)
	}

	return nil
}
