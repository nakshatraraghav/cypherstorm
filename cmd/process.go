package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
	"github.com/nakshatraraghav/cypherstorm/internal/pipeline"
	"github.com/spf13/cobra"
)

var (
	inputPath            string
	outputPath           string
	password             string
	compressionAlgorithm string
	encryptionAlgorithm  string
)

var processCmd = &cobra.Command{
	Use:   "process",
	Short: "Compress and encrypt files or directories in a secure pipeline",
	Long: `The "process" command allows you to compress and encrypt a specified file or directory. 
It provides options to choose the compression and encryption algorithms, ensuring secure and efficient storage or transfer of data.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmp := compression.NewGzipCompressor()
		enc := encryption.NewAesGcmEncryptor()

		err := pipeline.ProcessPipeline(inputPath, outputPath, password, cmp, enc)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(processCmd)

	processCmd.Flags().StringVar(&inputPath, "input-path", "", "input path of the files to process")
	processCmd.Flags().StringVar(&outputPath, "output-path", "", "choose where you want the processed file to output to")
	processCmd.Flags().StringVar(&password, "password", "", "password to encrypt the files with (optional)")
	processCmd.Flags().StringVar(&compressionAlgorithm, "compression-algo", "gzip", "choose the compression algorithm (optional)")
	processCmd.Flags().StringVar(&encryptionAlgorithm, "encryption-algo", "aes", "choose the encryption algorithm (optional)")

	processCmd.MarkFlagRequired("input-path")
	processCmd.MarkFlagRequired("output-path")
	processCmd.MarkFlagRequired("password")
}
