package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/spf13/cobra"
)

type protectOptions struct {
	inputPath         string
	outputPath        string
	keyFile           string
	credential        string
	passwordStdin     bool
	codec             string
	cipher            string
	overwrite         bool
	includes          []string
	excludes          []string
	excludeVCS        bool
	excludeCache      bool
	dryRun            bool
	verifyAfter       bool
	format            string
	recipients        []string
	passwordRecipient bool
	credentialHint    string
	publicHint        string
	ackPublicMetadata bool
}

func newProtectCommand(service Service, streams Streams) *cobra.Command {
	options := protectOptions{}
	command := &cobra.Command{
		Use:   "protect",
		Short: "Archive, compress, and encrypt a file or directory",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var credential app.Credential
			var err error
			needsCredential := options.format != "v2" || options.passwordRecipient || options.keyFile != "" || options.passwordStdin || options.credential != "" || len(options.recipients) == 0
			if !options.dryRun && needsCredential {
				credential, err = resolveCredentialChoice(command, service, streams, options.credential, options.keyFile, options.passwordStdin, true)
				if err != nil {
					return err
				}
				defer clearBytes(credential.Password)
				defer clearBytes(credential.RawKey)
			}
			if options.publicHint != "" && !options.ackPublicMetadata {
				return fmt.Errorf("cli: --public-hint requires --acknowledge-public-metadata")
			}
			result, err := service.Protect(command.Context(), app.ProtectRequest{
				InputPath:      options.inputPath,
				OutputPath:     options.outputPath,
				Credential:     credential,
				Cipher:         crypto.CipherID(options.cipher),
				Codec:          compress.CompressionID(options.codec),
				Overwrite:      options.overwrite,
				Includes:       options.includes,
				Excludes:       options.excludes,
				ExcludeVCS:     options.excludeVCS,
				ExcludeCache:   options.excludeCache,
				DryRun:         options.dryRun,
				VerifyAfter:    options.verifyAfter,
				Format:         options.format,
				RecipientPaths: options.recipients,
				CredentialHint: options.credentialHint,
				PublicHint:     options.publicHint,
			}, eventSink(command, "protect"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				return writeJSON(command, "protect", result)
			}
			if result.DryRun {
				_, err = fmt.Fprintf(command.OutOrStdout(), "dry run: %d included entries (%d bytes), %d excluded; output would be %s\n", result.Selection.IncludedEntries, result.Selection.IncludedBytes, result.Selection.ExcludedEntries, result.OutputPath)
			} else {
				_, err = fmt.Fprintf(command.OutOrStdout(), "protected %s (%d bytes)\n", result.OutputPath, result.OutputBytes)
			}
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "input file, directory, or symlink")
	flags.StringVar(&options.outputPath, "output-path", "", "protected output file")
	flags.StringVar(&options.keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.StringVar(&options.credential, "credential", "", "saved OS-keychain credential name")
	flags.BoolVar(&options.passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	flags.StringVar(&options.codec, "compression", options.codec, "compression codec: gzip, zstd, lz4, bzip2, or lzma")
	flags.StringVar(&options.cipher, "cipher", options.cipher, "cipher suite: aes-256-gcm or xchacha20poly1305")
	flags.BoolVar(&options.overwrite, "overwrite", false, "atomically replace an existing protected output")
	flags.StringSliceVar(&options.includes, "include", nil, "include portable glob (repeatable)")
	flags.StringSliceVar(&options.excludes, "exclude", nil, "exclude portable glob (repeatable)")
	flags.BoolVar(&options.excludeVCS, "exclude-vcs", false, "exclude version-control metadata")
	flags.BoolVar(&options.excludeCache, "exclude-cache", false, "exclude common cache directories")
	flags.BoolVar(&options.dryRun, "dry-run", false, "preview selection without deriving a key or writing an artifact")
	flags.BoolVar(&options.verifyAfter, "verify-after", false, "reopen and fully verify the published artifact")
	flags.StringVar(&options.format, "format", "v1", "protected format: v1 or v2")
	flags.StringSliceVar(&options.recipients, "recipient", nil, "v2 X25519 public recipient file")
	flags.BoolVar(&options.passwordRecipient, "password-recipient", false, "add a v2 password recipient")
	flags.StringVar(&options.credentialHint, "credential-hint", "", "encrypted private credential hint")
	flags.StringVar(&options.publicHint, "public-hint", "", "public credential hint (leaks metadata)")
	flags.BoolVar(&options.ackPublicMetadata, "acknowledge-public-metadata", false, "acknowledge that public hints are visible without authentication")
	return command
}
