package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

type interfaceWriter = io.Writer

func newBatchCommand(service Service, streams Streams) *cobra.Command {
	root := &cobra.Command{Use: "batch", Short: "Protect or restore multiple inputs", Args: cobra.NoArgs}
	var destination, keyFile, credentialName string
	var passwordStdin, continueOnError bool
	common := func(c *cobra.Command) {
		f := c.Flags()
		f.StringVar(&destination, "destination", "", "destination directory")
		f.StringVar(&keyFile, "key-file", "", "raw-key file")
		f.StringVar(&credentialName, "credential", "", "saved credential name")
		f.BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
		f.BoolVar(&continueOnError, "continue-on-error", false, "continue after an item fails")
	}
	protect := &cobra.Command{Use: "protect INPUT...", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cred, e := resolveCredentialChoice(cmd, service, streams, credentialName, keyFile, passwordStdin, true)
		if e != nil {
			return e
		}
		defer clearBytes(cred.Password)
		defer clearBytes(cred.RawKey)
		r, e := service.BatchProtect(cmd.Context(), app.BatchProtectRequest{Inputs: args, Destination: destination, Credential: cred, Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip, ContinueOnError: continueOnError}, eventSink(cmd, "batch.protect"))
		if e != nil && !continueOnError {
			return e
		}
		return writeResult(cmd, "batch.protect", r, func(w interfaceWriter) error {
			_, e := fmt.Fprintf(w, "%d succeeded, %d failed\n", r.Succeeded, r.Failed)
			return e
		})
	}}
	common(protect)
	restore := &cobra.Command{Use: "restore INPUT...", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cred, e := resolveCredentialChoice(cmd, service, streams, credentialName, keyFile, passwordStdin, false)
		if e != nil {
			return e
		}
		defer clearBytes(cred.Password)
		defer clearBytes(cred.RawKey)
		r, e := service.BatchRestore(cmd.Context(), app.BatchRestoreRequest{Inputs: args, Destination: destination, Credential: cred, ContinueOnError: continueOnError, Conflict: app.ConflictFail}, eventSink(cmd, "batch.restore"))
		if e != nil && !continueOnError {
			return e
		}
		return writeResult(cmd, "batch.restore", r, func(w interfaceWriter) error {
			_, e := fmt.Fprintf(w, "%d succeeded, %d failed\n", r.Succeeded, r.Failed)
			return e
		})
	}}
	common(restore)
	root.AddCommand(protect, restore)
	return root
}

func newManifestCommand(service Service) *cobra.Command {
	root := &cobra.Command{Use: "manifest", Short: "Create and verify deterministic tree manifests", Args: cobra.NoArgs}
	var output string
	create := &cobra.Command{Use: "create PATH", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: plain manifests reveal names, sizes, structure, and hashes")
		r, e := service.ManifestCreate(cmd.Context(), args[0], output)
		if e != nil {
			return e
		}
		return writeJSON(cmd, "manifest.create", r)
	}}
	create.Flags().StringVar(&output, "output", "", "manifest output path")
	_ = create.MarkFlagRequired("output")
	verify := &cobra.Command{Use: "verify PATH MANIFEST", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.ManifestVerify(cmd.Context(), args[0], args[1])
		if e != nil {
			return e
		}
		return writeJSON(cmd, "manifest.verify", r)
	}}
	root.AddCommand(create, verify)
	return root
}
func newCompareCommand(service Service) *cobra.Command {
	return &cobra.Command{Use: "compare LEFT RIGHT", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.Compare(cmd.Context(), args[0], args[1])
		if e != nil {
			return e
		}
		return writeResult(cmd, "compare", r, func(w interfaceWriter) error {
			if r.Equal {
				_, e = fmt.Fprintln(w, "equal")
			} else {
				for _, c := range r.Changes {
					_, e = fmt.Fprintf(w, "%s\t%s\n", c.Kind, c.Path)
					if e != nil {
						return e
					}
				}
			}
			return e
		})
	}}
}
func newRecommendCommand(service Service) *cobra.Command {
	var optimize, mode string
	c := &cobra.Command{Use: "recommend INPUT", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.Recommend(cmd.Context(), app.RecommendRequest{InputPath: args[0], Optimize: optimize, Mode: mode}, eventSink(cmd, "recommend"))
		if e != nil {
			return e
		}
		return writeResult(cmd, "recommend", r, func(w interfaceWriter) error {
			label := "complete"
			if r.Estimated {
				label = "sampled estimate"
			}
			_, e = fmt.Fprintf(w, "%s/%s (%s, optimize %s)\n", r.Combination.Codec, r.Combination.Cipher, label, r.Optimize)
			return e
		})
	}}
	c.Flags().StringVar(&optimize, "optimize", "balanced", "balanced, size, protect-speed, or restore-speed")
	c.Flags().StringVar(&mode, "mode", "full", "full or sample")
	return c
}
func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			return root.GenPowerShellCompletion(cmd.OutOrStdout())
		default:
			return fmt.Errorf("unsupported shell %q", args[0])
		}
	}}
}
func newDocsCommand(root *cobra.Command) *cobra.Command {
	var output string
	c := &cobra.Command{Use: "docs man", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "man" {
			return fmt.Errorf("only man documentation is supported")
		}
		if err := os.MkdirAll(output, 0o755); err != nil {
			return err
		}
		return doc.GenManTree(root, nil, output)
	}}
	c.Flags().StringVar(&output, "output", "", "output directory")
	_ = c.MarkFlagRequired("output")
	return c
}
