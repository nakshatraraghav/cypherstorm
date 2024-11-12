package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "cypherstorm",
	Short:   "A powerful suite for file compression, encryption and hashing",
	Long:    "CypherStorm is a cryptographic suite of tools for compressing, encrypting, and hashing files or folders with customizable algorithms, providing flexible, high-security file management",
	Aliases: []string{"cypher", "cstorm"},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
