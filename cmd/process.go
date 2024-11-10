package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var processCmd = &cobra.Command{
	Use:   "process",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("process cmd run")
	},
}

func init() {
	rootCmd.AddCommand(processCmd)
}
