package cli

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

func newRekeyCommand(service Service, streams Streams) *cobra.Command {
	var output, keyFile, credentialName, newKeyFile string
	var passwordStdin, newPassword bool
	var identities, addRecipients, removeRecipients []string
	c := &cobra.Command{Use: "rekey ARCHIVE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var current app.Credential
		var e error
		if needsSymmetricCredential(identities, keyFile, credentialName, passwordStdin) {
			current, e = resolveCredentialChoice(cmd, service, streams, credentialName, keyFile, passwordStdin, false)
			if e != nil {
				return e
			}
			defer clearBytes(current.Password)
			defer clearBytes(current.RawKey)
		}
		var replacement app.Credential
		if newKeyFile != "" {
			key, e := readRawKeyFile(newKeyFile)
			if e != nil {
				return e
			}
			replacement = app.Credential{Kind: app.CredentialRawKey, RawKey: key}
			defer clearBytes(key)
		} else if newPassword {
			replacement, e = resolveCredential(streams, "", false, true)
			if e != nil {
				return e
			}
			defer clearBytes(replacement.Password)
		}
		r, e := service.Rekey(cmd.Context(), app.RekeyRequest{InputPath: args[0], OutputPath: output, Credential: current, IdentityPaths: identities, NewCredential: replacement, AddRecipientPaths: addRecipients, RemoveRecipientIDs: removeRecipients}, eventSink(cmd, "rekey"))
		if e != nil {
			return e
		}
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: rekeying invalidates detached signatures and cannot revoke older archive copies")
		return writeJSON(cmd, "rekey", r)
	}}
	f := c.Flags()
	f.StringVar(&output, "output", "", "rekeyed output path")
	_ = c.MarkFlagRequired("output")
	f.StringVar(&keyFile, "key-file", "", "current raw-key file")
	f.StringVar(&credentialName, "credential", "", "current saved credential")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read current password from stdin")
	f.StringSliceVar(&identities, "identity", nil, "current private X25519 identity")
	f.BoolVar(&newPassword, "new-password", false, "prompt for a replacement password")
	f.StringVar(&newKeyFile, "new-key-file", "", "replacement raw-key file")
	f.StringSliceVar(&addRecipients, "add-recipient", nil, "add X25519 public recipient")
	f.StringSliceVar(&removeRecipients, "remove-recipient", nil, "remove recipient fingerprint")
	return c
}
func newRecipientCommand(service Service) *cobra.Command {
	var output string
	root := &cobra.Command{Use: "recipient", Args: cobra.NoArgs}
	importQR := &cobra.Command{Use: "import-qr IMAGE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.RecipientImportQR(cmd.Context(), args[0], output)
		if e != nil {
			return e
		}
		return writeJSON(cmd, "recipient.import-qr", r)
	}}
	importQR.Flags().StringVar(&output, "output", "", "public identity output")
	_ = importQR.MarkFlagRequired("output")
	root.AddCommand(importQR)
	return root
}
func addIdentityQRCommand(root *cobra.Command, service Service) {
	var output string
	qr := &cobra.Command{Use: "qr PUBLIC", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.IdentityQR(cmd.Context(), args[0], output)
		if e != nil {
			return e
		}
		if output == "" {
			_, e = fmt.Fprint(cmd.OutOrStdout(), r.Terminal)
			return e
		}
		return writeJSON(cmd, "identity.qr", r)
	}}
	qr.Flags().StringVar(&output, "output", "", "PNG output path")
	root.AddCommand(qr)
}
