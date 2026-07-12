package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

func newKeyCommand(service Service) *cobra.Command {
	root := &cobra.Command{Use: "key", Short: "Generate, validate, and identify raw keys", Args: cobra.NoArgs}
	var output, format string
	generate := &cobra.Command{Use: "generate", Short: "Generate a private 32-byte raw key", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, e := service.KeyGenerate(cmd.Context(), app.KeyGenerateRequest{OutputPath: output}, eventSink(cmd, "key.generate"))
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "key.generate", r)
		}
		_, e = fmt.Fprintf(cmd.OutOrStdout(), "generated %s\nfingerprint %s\n", r.Path, r.Fingerprint)
		return e
	}}
	generate.Flags().StringVar(&output, "output", "", "output key file (required)")
	_ = generate.MarkFlagRequired("output")
	generate.Flags().StringVar(&format, "output-format", "text", "output format: text or json")
	validate := &cobra.Command{Use: "validate KEY", Short: "Validate a raw-key file", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.KeyValidate(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "key.validate", r)
		}
		_, e = fmt.Fprintf(cmd.OutOrStdout(), "valid raw key %s (%s)\n", r.Path, r.Fingerprint)
		return e
	}}
	fingerprint := &cobra.Command{Use: "fingerprint KEY", Short: "Print a raw-key fingerprint", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.KeyFingerprint(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "key.fingerprint", r)
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), r.Fingerprint)
		return e
	}}
	root.AddCommand(generate, validate, fingerprint)
	return root
}
