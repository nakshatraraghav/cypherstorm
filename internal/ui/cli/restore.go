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
	credential    string
	passwordStdin bool
	includes      []string
	excludes      []string
	paths         []string
	conflict      string
	identities    []string
}

func newRestoreCommand(service Service, streams Streams) *cobra.Command {
	options := restoreOptions{}
	command := &cobra.Command{
		Use:   "restore",
		Short: "Authenticate, decrypt, decompress, and restore protected data",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var credential app.Credential
			var err error
			if needsSymmetricCredential(options.identities, options.keyFile, options.credential, options.passwordStdin) {
				credential, err = resolveCredentialChoice(command, service, streams, options.credential, options.keyFile, options.passwordStdin, false)
				if err != nil {
					return err
				}
				defer clearBytes(credential.Password)
				defer clearBytes(credential.RawKey)
			}
			result, err := service.Restore(command.Context(), app.RestoreRequest{
				InputPath:     options.inputPath,
				OutputPath:    options.outputPath,
				Credential:    credential,
				Includes:      options.includes,
				Excludes:      options.excludes,
				Paths:         options.paths,
				Conflict:      app.ConflictPolicy(options.conflict),
				IdentityPaths: options.identities,
			}, eventSink(command, "restore"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				return writeJSON(command, "restore", result)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "restored %s\n", result.OutputPath)
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "protected input file")
	flags.StringVar(&options.outputPath, "output-path", "", "new destination directory")
	flags.StringVar(&options.keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.StringVar(&options.credential, "credential", "", "saved OS-keychain credential name")
	flags.BoolVar(&options.passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	flags.StringSliceVar(&options.includes, "include", nil, "restore entries matching a portable glob")
	flags.StringSliceVar(&options.excludes, "exclude", nil, "exclude entries matching a portable glob")
	flags.StringSliceVar(&options.paths, "path", nil, "restore an exact path or directory subtree")
	flags.StringVar(&options.conflict, "conflict", string(app.ConflictFail), "existing destination policy: fail, skip, rename, or overwrite")
	flags.StringSliceVar(&options.identities, "identity", nil, "private X25519 identity file")
	return command
}
