package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

type resultEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
	Result        any    `json:"result"`
}

func writeJSON(command *cobra.Command, operation string, result any) error {
	encoder := json.NewEncoder(command.OutOrStdout())
	encoder.SetEscapeHTML(false)
	return encoder.Encode(resultEnvelope{SchemaVersion: 1, Operation: operation, Status: "success", Result: result})
}

func newInspectCommand(service Service, streams Streams) *cobra.Command {
	var keyFile, savedCredential string
	var authenticate, passwordStdin bool
	var identities []string
	command := &cobra.Command{
		Use: "inspect INPUT.cys", Short: "Inspect a protected-file header without a credential", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			var credential app.Credential
			var err error
			if authenticate && needsSymmetricCredential(identities, keyFile, savedCredential, passwordStdin) {
				credential, err = resolveCredentialChoice(command, service, streams, savedCredential, keyFile, passwordStdin, false)
				if err != nil {
					return err
				}
				defer clearBytes(credential.Password)
				defer clearBytes(credential.RawKey)
			}
			result, err := service.Inspect(command.Context(), app.InspectRequest{InputPath: args[0], Authenticate: authenticate, Credential: credential, IdentityPaths: identities}, eventSink(command, "inspect"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				return writeJSON(command, "inspect", result)
			}
			argon := ""
			if result.Argon2 != nil {
				argon = fmt.Sprintf("\nArgon2id: time=%d memory=%dKiB parallelism=%d", result.Argon2.Time, result.Argon2.MemoryKiB, result.Argon2.Parallelism)
			}
			warning := "Warning: header is structurally validated but unauthenticated"
			if result.HeaderAuthenticated {
				warning = "Header and private metadata authenticated"
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "Path: %s\nFormat: v%d\nCipher: %s\nCompression: %s\nCredential: %s\nRecord size: %d\nContainer bytes: %d%s\n%s\n", result.Path, result.FormatVersion, result.Cipher, result.Codec, credentialKindName(result.CredentialKind), result.RecordSize, result.ContainerBytes, argon, warning)
			if err == nil && result.PrivateMetadata != nil && result.PrivateMetadata.CredentialHint != "" {
				_, err = fmt.Fprintf(command.OutOrStdout(), "Credential hint: %s\n", neutralizeTerminal(result.PrivateMetadata.CredentialHint))
			}
			return err
		},
	}
	command.Flags().BoolVar(&authenticate, "authenticate", false, "authenticate and reveal private metadata")
	command.Flags().StringVar(&keyFile, "key-file", "", "raw-key file")
	command.Flags().StringVar(&savedCredential, "credential", "", "saved credential name")
	command.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	command.Flags().StringSliceVar(&identities, "identity", nil, "private X25519 identity file")
	return command
}

func newVerifyCommand(service Service, streams Streams) *cobra.Command {
	var keyFile, savedCredential, mode string
	var passwordStdin bool
	var identities []string
	command := &cobra.Command{
		Use: "verify INPUT.cys", Short: "Authenticate and validate a protected archive", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			var credential app.Credential
			var err error
			if needsSymmetricCredential(identities, keyFile, savedCredential, passwordStdin) {
				credential, err = resolveCredentialChoice(command, service, streams, savedCredential, keyFile, passwordStdin, false)
				if err != nil {
					return err
				}
				defer clearBytes(credential.Password)
				defer clearBytes(credential.RawKey)
			}
			result, err := service.Verify(command.Context(), app.VerifyRequest{InputPath: args[0], Credential: credential, Mode: app.VerifyMode(mode), IdentityPaths: identities}, eventSink(command, "verify"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				return writeJSON(command, "verify", result)
			}
			if result.ArchiveValidated {
				_, err = fmt.Fprintf(command.OutOrStdout(), "verified %s: authenticated container and valid archive (%d entries, %d bytes)\n", result.Path, result.Summary.Entries, result.Summary.Bytes)
			} else {
				_, err = fmt.Fprintf(command.OutOrStdout(), "credential accepted for %s; quick mode did not validate the decompressed archive\n", result.Path)
			}
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.StringVar(&savedCredential, "credential", "", "saved OS-keychain credential name")
	flags.BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	flags.StringSliceVar(&identities, "identity", nil, "private X25519 identity file")
	flags.StringVar(&mode, "mode", string(app.VerifyFull), "verification mode: quick or full")
	return command
}

func newListCommand(service Service, streams Streams) *cobra.Command {
	var keyFile, savedCredential, match string
	var passwordStdin, long, summaryOnly, filesOnly bool
	var maxDepth int
	var identities []string
	command := &cobra.Command{
		Use: "list INPUT.cys", Short: "Authenticate and list protected archive contents", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			var credential app.Credential
			var err error
			if needsSymmetricCredential(identities, keyFile, savedCredential, passwordStdin) {
				credential, err = resolveCredentialChoice(command, service, streams, savedCredential, keyFile, passwordStdin, false)
				if err != nil {
					return err
				}
				defer clearBytes(credential.Password)
				defer clearBytes(credential.RawKey)
			}
			result, err := service.List(command.Context(), app.ListRequest{InputPath: args[0], Credential: credential, FilesOnly: filesOnly, MaxDepth: maxDepth, Match: match, IdentityPaths: identities}, eventSink(command, "list"))
			if err != nil {
				return err
			}
			if outputFormat(command) == "json" {
				return writeJSON(command, "list", result)
			}
			if !summaryOnly {
				for _, entry := range result.Entries {
					path := neutralizeTerminal(entry.Path)
					if long {
						_, err = fmt.Fprintf(command.OutOrStdout(), "%-9s %10d %04o %s", entry.Type, entry.Size, entry.Mode.Perm(), path)
						if entry.LinkTarget != "" {
							_, err = fmt.Fprintf(command.OutOrStdout(), " -> %s", neutralizeTerminal(entry.LinkTarget))
						}
						_, _ = fmt.Fprintln(command.OutOrStdout())
					} else {
						_, err = fmt.Fprintln(command.OutOrStdout(), path)
					}
					if err != nil {
						return err
					}
				}
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "%d entries, %d files, %d bytes\n", result.Summary.Entries, result.Summary.Files, result.Summary.Bytes)
			return err
		},
	}
	flags := command.Flags()
	flags.StringVar(&keyFile, "key-file", "", "path to an exact 32-byte binary raw-key file")
	flags.StringVar(&savedCredential, "credential", "", "saved OS-keychain credential name")
	flags.BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	flags.StringSliceVar(&identities, "identity", nil, "private X25519 identity file")
	flags.BoolVar(&long, "long", false, "show type, size, mode, and symlink targets")
	flags.BoolVar(&summaryOnly, "summary", false, "show only the archive summary")
	flags.BoolVar(&filesOnly, "files-only", false, "show regular files only")
	flags.IntVar(&maxDepth, "max-depth", 0, "maximum displayed path depth (zero is unlimited)")
	flags.StringVar(&match, "match", "", "display entries matching a portable glob")
	return command
}

func credentialKindName(kind app.CredentialKind) string {
	if kind == app.CredentialRawKey {
		return "raw-key"
	}
	if kind == app.CredentialPassword {
		return "password"
	}
	return "unknown"
}
func neutralizeTerminal(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '�'
		}
		return r
	}, value)
}
