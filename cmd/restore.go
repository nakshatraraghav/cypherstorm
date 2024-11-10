package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("restore command run")
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)
}
