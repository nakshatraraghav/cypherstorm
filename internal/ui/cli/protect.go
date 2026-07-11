package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/spf13/cobra"
)

type protectOptions struct {
	inputPath     string
	outputPath    string
	keyFile       string
	passwordStdin bool
	codec         string
	cipher        string
	overwrite     bool
}

func newProtectCommand(service Service, streams Streams) *cobra.Command {
	options := protectOptions{
		codec:  string(compress.CompressionGzip),
		cipher: string(crypto.AES256GCM),
	}
	command := &cobra.Command{
		Use:   "protect",
		Short: "Archive, compress, and encrypt a file or directory",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			credential, err := resolveCredential(streams, options.keyFile, options.passwordStdin, true)
			if err != nil {
				return err
			}
			defer clearBytes(credential.Password)
			defer clearBytes(credential.RawKey)
			result, err := service.Protect(command.Context(), app.ProtectRequest{
				InputPath:  options.inputPath,
				OutputPath: options.outputPath,
				Credential: credential,
				Cipher:     crypto.CipherID(options.cipher),
				Codec:      compress.CompressionID(options.codec),
				Overwrite:  options.overwrite,
			}, nil)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "protected %s (%d bytes)\n", result.OutputPath, result.OutputBytes)
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "input file, directory, or symlink")
	flags.StringVar(&options.outputPath, "output-path", "", "protected output file")
	flags.StringVar(&options.keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.BoolVar(&options.passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	flags.StringVar(&options.codec, "compression", options.codec, "compression codec: gzip, zstd, lz4, bzip2, or lzma")
	flags.StringVar(&options.cipher, "cipher", options.cipher, "cipher suite: aes-256-gcm or xchacha20poly1305")
	flags.BoolVar(&options.overwrite, "overwrite", false, "atomically replace an existing protected output")
	return command
}
