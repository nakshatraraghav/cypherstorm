package cli

import (
	"encoding/hex"
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
	"github.com/spf13/cobra"
)

type hashOptions struct {
	inputPath string
	algorithm string
}

func newHashCommand(service Service) *cobra.Command {
	options := hashOptions{algorithm: string(hashing.SHA256)}
	command := &cobra.Command{
		Use:   "hash",
		Short: "Hash regular files without following symlinks",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			results, err := service.Hash(command.Context(), app.HashRequest{
				InputPath: options.inputPath,
				Algorithm: hashing.ID(options.algorithm),
			}, eventSink(command, "hash"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				type hashDTO struct {
					Path   string `json:"path"`
					Digest string `json:"digest"`
				}
				dto := make([]hashDTO, len(results))
				for i, result := range results {
					dto[i] = hashDTO{Path: result.Path, Digest: hex.EncodeToString(result.Digest)}
				}
				return writeJSON(command, "hash", dto)
			}
			for _, result := range results {
				if _, err := fmt.Fprintf(command.OutOrStdout(), "%s  %s\n", hex.EncodeToString(result.Digest), result.Path); err != nil {
					return fmt.Errorf("cli: write hash result: %w", err)
				}
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "regular file or directory to hash")
	flags.StringVar(&options.algorithm, "algorithm", options.algorithm, "hash algorithm: sha256, sha384, or sha512")
	return command
}
