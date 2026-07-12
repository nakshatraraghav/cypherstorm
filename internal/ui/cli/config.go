package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newConfigCommand(service Service) *cobra.Command {
	root := &cobra.Command{Use: "config", Short: "Inspect and validate non-secret configuration", Args: cobra.NoArgs}
	var effective bool
	show := &cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, e := service.ConfigShow(cmd.Context(), effective)
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(r, "", "  ")
		if e == nil {
			_, e = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		}
		return e
	}}
	show.Flags().BoolVar(&effective, "effective", false, "show resolved effective policy")
	validate := &cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, e := service.ConfigValidate(cmd.Context())
		if e != nil {
			return e
		}
		_, e = fmt.Fprintf(cmd.OutOrStdout(), "valid configuration %s\n", r.Path)
		return e
	}}
	pathCmd := &cobra.Command{Use: "path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, e := service.ConfigShow(cmd.Context(), false)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), r.Path)
		return e
	}}
	root.AddCommand(show, validate, pathCmd)
	return root
}
func newPolicyCommand(service Service) *cobra.Command {
	return &cobra.Command{Use: "policy show NAME", Short: "Show a resolved policy profile", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "show" {
			return fmt.Errorf("expected policy show NAME")
		}
		p, e := service.PolicyShow(cmd.Context(), args[1])
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(p, "", "  ")
		if e == nil {
			_, e = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		}
		return e
	}}
}
