package utils

import (
	"fmt"
	"os"

	"github.com/nakshatraraghav/cypherstorm/internal/keyman"
)

func ResolvePasswordFromFlags(password, keyFilePath string) ([]byte, error) {
	keyManager := keyman.NewKeyManager(32, 16)

	if password != "" && keyFilePath != "" {
		return nil, fmt.Errorf("only one of --password or --password-file can be specified, not both")
	}

	if password != "" {
		return keyManager.DeriveKeyFromPassword(password)
	}

	if keyFilePath != "" {
		content, err := os.ReadFile(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read the contents of the password file: %v", err)
		}

		return content, nil
	}

	return nil, nil
}
