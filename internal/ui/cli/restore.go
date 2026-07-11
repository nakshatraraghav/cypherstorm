package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

type restoreOptions struct {
	inputPath     string
	outputPath    string
	keyFile       string
	passwordStdin bool
}

func newRestoreCommand(service Service, streams Streams) *cobra.Command {
	options := restoreOptions{}
	command := &cobra.Command{
		Use:   "restore",
		Short: "Authenticate, decrypt, decompress, and restore protected data",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			credential, err := resolveCredential(streams, options.keyFile, options.passwordStdin, false)
			if err != nil {
				return err
			}
			defer clearBytes(credential.Password)
			defer clearBytes(credential.RawKey)
			result, err := service.Restore(command.Context(), app.RestoreRequest{
				InputPath:  options.inputPath,
				OutputPath: options.outputPath,
				Credential: credential,
			}, nil)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "restored %s\n", result.OutputPath)
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "protected input file")
	flags.StringVar(&options.outputPath, "output-path", "", "new destination directory")
	flags.StringVar(&options.keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.BoolVar(&options.passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	return command
}
