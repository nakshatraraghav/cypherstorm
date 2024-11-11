package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/nakshatraraghav/cypherstorm/internal/archiver"
	"github.com/nakshatraraghav/cypherstorm/internal/compression"
	"github.com/nakshatraraghav/cypherstorm/internal/encryption"
	"github.com/nakshatraraghav/cypherstorm/internal/keyman"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "cypherstorm",
	Short:   "A powerful suite for file compression, encryption and hashing",
	Long:    "CypherStorm is a cryptographic suite of tools for compressing, encrypting, and hashing files or folders with customizable algorithms, providing flexible, high-security file management",
	Aliases: []string{"cypher", "cstorm"},
	Run: func(cmd *cobra.Command, args []string) {
		err := archiver.CreateTarArchive("/home/combatrickshaw/Downloads/test", "/home/combatrickshaw/Downloads/archive.tar")
		if err != nil {
			log.Fatal(err)
		}

		cmp := compression.NewGzipCompressor()

		archive, err := os.Open("/home/combatrickshaw/Downloads/archive.tar")
		if err != nil {
			log.Fatal(err)
		}

		compressed, err := os.Create("/home/combatrickshaw/Downloads/archive.tar.cmp")
		if err != nil {
			log.Fatal(err)
		}

		err = cmp.Compress(archive, compressed)
		if err != nil {
			log.Fatal(err)
		}

		km := keyman.NewKeyManager(32, 16)
		key, err := km.DeriveKeyFromPassword("helloworld")
		if err != nil {
			log.Fatal(err)
		}

		enc := encryption.NewAesGcmEncryptor(key)

		compressedArchive, err := os.Open("/home/combatrickshaw/Downloads/archive.tar.cmp")
		if err != nil {
			log.Fatal(err)
		}

		encrypted, err := os.Create("/home/combatrickshaw/Downloads/archive.tar.cmp.enc")
		if err != nil {
			log.Fatal(err)
		}

		err = enc.Encrypt(compressedArchive, encrypted)
		if err != nil {
			log.Fatal(err)
		}

		encryptedFile, err := os.Open("/home/combatrickshaw/Downloads/archive.tar.cmp.enc")
		if err != nil {
			log.Fatal(err)
		}

		decrypted, err := os.Create("/home/combatrickshaw/Downloads/decrypted.tar.cmp")
		if err != nil {
			log.Fatal(err)
		}

		err = enc.Decrypt(encryptedFile, decrypted)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
