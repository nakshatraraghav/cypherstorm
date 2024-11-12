package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/pipeline"
	"github.com/spf13/cobra"
)

var (
	algorithm string
)

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Calculate and display file hashes",
	Long: `The "hash" command allows you to calculate and display the hash values of files or directories.
You can choose from a variety of hashing algorithms, including MD5, SHA1, SHA256, SHA384, and SHA512.
The command will walk through the specified input path and print the hash value for each file.`,
	Run: func(cmd *cobra.Command, args []string) {
		hasher, err := hashing.NewHasher(algorithm)
		if err != nil {
			log.Fatal(err)
		}
		err = pipeline.CalculateHashPipeline(inputPath, hasher)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)

	hashCmd.Flags().StringVar(&inputPath, "input-path", "", "input path of the file/files you want to hash")
	hashCmd.Flags().StringVar(&algorithm, "algorithm", "sha256", "choose required hashing algorithm")

	hashCmd.MarkFlagRequired("input-path")
}
