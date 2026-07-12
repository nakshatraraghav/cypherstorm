package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

func resolveCredentialChoice(ctx *cobra.Command, service Service, streams Streams, name, keyFile string, passwordStdin, confirm bool) (app.Credential, error) {
	if name != "" {
		if keyFile != "" || passwordStdin {
			return app.Credential{}, fmt.Errorf("cli: --credential cannot be combined with --key-file or --password-stdin")
		}
		return service.ResolveSavedCredential(ctx.Context(), name)
	}
	return resolveCredential(streams, keyFile, passwordStdin, confirm)
}

func newCredentialCommand(service Service, streams Streams) *cobra.Command {
	root := &cobra.Command{Use: "credential", Short: "Manage credentials in the operating-system keychain", Args: cobra.NoArgs}
	var keyFile string
	var passwordStdin bool
	add := &cobra.Command{Use: "add NAME", Short: "Save a password or raw key", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		c, e := resolveCredential(streams, keyFile, passwordStdin, false)
		if e != nil {
			return e
		}
		defer clearBytes(c.Password)
		defer clearBytes(c.RawKey)
		d, e := service.CredentialAdd(cmd.Context(), args[0], c)
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "credential.add", d)
		}
		_, e = fmt.Fprintf(cmd.OutOrStdout(), "saved %s credential %s", d.Kind, d.Name)
		if d.Fingerprint != "" {
			_, e = fmt.Fprintf(cmd.OutOrStdout(), " (%s)", d.Fingerprint)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
		return e
	}}
	add.Flags().StringVar(&keyFile, "key-file", "", "path to a raw-key file")
	add.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	list := &cobra.Command{Use: "list", Short: "List non-secret credential descriptors", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		items, e := service.CredentialList(cmd.Context())
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "credential.list", items)
		}
		for _, d := range items {
			if _, e = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", d.Name, d.Kind, d.Fingerprint); e != nil {
				return e
			}
		}
		return nil
	}}
	inspect := &cobra.Command{Use: "inspect NAME", Short: "Inspect a non-secret credential descriptor", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		d, e := service.CredentialInspect(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "credential.inspect", d)
		}
		_, e = fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\nKind: %s\nFingerprint: %s\n", d.Name, d.Kind, d.Fingerprint)
		return e
	}}
	remove := &cobra.Command{Use: "remove NAME", Short: "Remove a saved credential", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if e := service.CredentialRemove(cmd.Context(), args[0]); e != nil {
			return e
		}
		if outputFormat(cmd) == "json" {
			return writeJSON(cmd, "credential.remove", map[string]string{"name": args[0]})
		}
		_, e := fmt.Fprintf(cmd.OutOrStdout(), "removed credential %s\n", args[0])
		return e
	}}
	root.AddCommand(add, list, inspect, remove)
	return root
}
