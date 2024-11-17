package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/constants"
	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
	"github.com/nakshatraraghav/cypherstorm/internal/pipeline"
	"github.com/nakshatraraghav/cypherstorm/utils"
	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Decompress and decrypt files in a secure pipeline",
	Long: `The "restore" command allows you to decompress and decrypt a specified file or directory.
It provides options to choose the compression and encryption algorithms, ensuring the recovery of the original data.

Available Compression Algorithms:
  - gzip
  - bzip2
  - lz4
  - lzma
  - zstd

Available Encryption Algorithms:
  - aes-256-gcm
  - xchacha20poly1305`,
	Run: func(cmd *cobra.Command, args []string) {
		password, err := utils.ResolvePasswordFromFlags(password, keyFilePath)
		if err != nil {
			log.Fatal(err)
		}

		cmp, err := compression.NewCompressor(compressionAlgorithm)
		if err != nil {
			log.Fatal(err)
		}

		dec, err := encryption.NewEncryptor(encryptionAlgorithm)
		if err != nil {
			log.Fatal(err)
		}

		err = pipeline.DataRecoveryPipeline(inputPath, outputPath, password, cmp, dec)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().StringVar(&inputPath, "input-path", "", "input path of the files to process")
	restoreCmd.Flags().StringVar(&outputPath, "output-path", "", "choose where you want the processed file to output to")
	restoreCmd.Flags().StringVar(&password, "password", "", "password to encrypt the files with (optional)")
	restoreCmd.Flags().StringVar(&keyFilePath, "key-file-path", "", "file containing the password to encrypt the files with (optional)")
	restoreCmd.Flags().StringVar(&compressionAlgorithm, "compression-algo", constants.GZIP, "choose the compression algorithm (optional)")
	restoreCmd.Flags().StringVar(&encryptionAlgorithm, "encryption-algo", constants.AES_256_GCM, "choose the encryption algorithm (optional)")

	restoreCmd.MarkFlagRequired("input-path")
	restoreCmd.MarkFlagRequired("output-path")
}
