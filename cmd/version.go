package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "cypherstorm version",
	Long:  "Get the version of cypherstorm utility currently in use",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Pre-Release")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
