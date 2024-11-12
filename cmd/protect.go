package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
	"github.com/nakshatraraghav/cypherstorm/internal/pipeline"
	"github.com/nakshatraraghav/cypherstorm/utils"
	"github.com/spf13/cobra"
)

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Compress and encrypt files or directories in a secure pipeline",
	Long: `The "protect" command allows you to compress and encrypt a specified file or directory. 
It provides options to choose the compression and encryption algorithms, ensuring secure and efficient storage or transfer of data.`,
	Run: func(cmd *cobra.Command, args []string) {

		password, err := utils.ResolvePasswordFromFlags(password, keyFilePath)
		if err != nil {
			log.Fatal(err)
		}

		cmp := compression.NewGzipCompressor()
		enc := encryption.NewAesGcmEncryptor()

		err = pipeline.DataProtectionPipeline(inputPath, outputPath, password, cmp, enc)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(protectCmd)

	protectCmd.Flags().StringVar(&inputPath, "input-path", "", "input path of the files to process")
	protectCmd.Flags().StringVar(&outputPath, "output-path", "", "choose where you want the processed file to output to")
	protectCmd.Flags().StringVar(&password, "password", "", "password to encrypt the files with (optional)")
	protectCmd.Flags().StringVar(&keyFilePath, "key-file-path", "", "file containing the password to encrypt the files with (optional)")
	protectCmd.Flags().StringVar(&compressionAlgorithm, "compression-algo", "gzip", "choose the compression algorithm (optional)")
	protectCmd.Flags().StringVar(&encryptionAlgorithm, "encryption-algo", "aes", "choose the encryption algorithm (optional)")

	protectCmd.MarkFlagRequired("input-path")
	protectCmd.MarkFlagRequired("output-path")
}
