package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/constants"
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

Available Hashing Algorithms:
- md5
- sha1
- sha256
- sha384
- sha512
	`,
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
	hashCmd.Flags().StringVar(&algorithm, "algorithm", constants.SHA256, "choose required hashing algorithm. Available algorithms: md5, sha1, sha256, sha384, sha512")

	hashCmd.MarkFlagRequired("input-path")
}
