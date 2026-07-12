package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newIdentityCommand(service Service) *cobra.Command {
	root := &cobra.Command{Use: "identity", Short: "Manage signing and X25519 identities", Args: cobra.NoArgs}
	var kind, output string
	generate := &cobra.Command{Use: "generate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, e := service.IdentityGenerate(cmd.Context(), kind, output)
		if e != nil {
			return e
		}
		return writeResult(cmd, "identity.generate", r, func(w interfaceWriter) error {
			_, e = fmt.Fprintf(w, "generated %s identity %s\nfingerprint %s\n", r.Type, r.Path, r.Fingerprint)
			return e
		})
	}}
	generate.Flags().StringVar(&kind, "type", "x25519", "identity type: x25519 or signing")
	generate.Flags().StringVar(&output, "output", "", "private identity output")
	_ = generate.MarkFlagRequired("output")
	var publicOutput string
	public := &cobra.Command{Use: "public PRIVATE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.IdentityPublic(cmd.Context(), args[0], publicOutput)
		if e != nil {
			return e
		}
		return writeJSON(cmd, "identity.public", r)
	}}
	public.Flags().StringVar(&publicOutput, "output", "", "public identity output")
	_ = public.MarkFlagRequired("output")
	fingerprint := &cobra.Command{Use: "fingerprint PUBLIC", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.IdentityFingerprint(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), r.Fingerprint)
		return e
	}}
	root.AddCommand(generate, public, fingerprint)
	addIdentityQRCommand(root, service)
	return root
}
func newSignCommand(service Service) *cobra.Command {
	var private, output, label string
	c := &cobra.Command{Use: "sign ARCHIVE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if output == "" {
			output = args[0] + ".sig"
		}
		r, e := service.Sign(cmd.Context(), args[0], private, output, label)
		if e != nil {
			return e
		}
		return writeJSON(cmd, "sign", r)
	}}
	c.Flags().StringVar(&private, "identity", "", "signing private identity")
	_ = c.MarkFlagRequired("identity")
	c.Flags().StringVar(&output, "output", "", "signature output")
	c.Flags().StringVar(&label, "label", "", "bounded public signer label")
	return c
}
func newSignatureCommand(service Service) *cobra.Command {
	root := &cobra.Command{Use: "signature", Args: cobra.NoArgs}
	inspect := &cobra.Command{Use: "inspect SIGNATURE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.SignatureInspect(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		return writeJSON(cmd, "signature.inspect", r)
	}}
	var trustedSigner string
	verify := &cobra.Command{Use: "verify ARCHIVE SIGNATURE", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		r, e := service.SignatureVerify(cmd.Context(), args[0], args[1], trustedSigner)
		if e != nil {
			return e
		}
		return writeResult(cmd, "signature.verify", r, func(w interfaceWriter) error {
			_, e = fmt.Fprintf(w, "valid signature from %s\n", r.SignerFingerprint)
			return e
		})
	}}
	verify.Flags().StringVar(&trustedSigner, "signer", "", "trusted signing public identity path or fingerprint")
	_ = verify.MarkFlagRequired("signer")
	root.AddCommand(inspect, verify)
	return root
}
