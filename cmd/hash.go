package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hash command run")
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
}
