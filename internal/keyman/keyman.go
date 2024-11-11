package keyman

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

type KeyManager struct {
	keySize  int
	saltSize int
}

func NewKeyManager(keySize, saltSize int) *KeyManager {
	return &KeyManager{
		keySize:  keySize,
		saltSize: saltSize,
	}
}

func (km *KeyManager) DeriveKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, km.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate a salt for password : %v", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		1,
		64*1024,
		4,
		32,
	)

	return key, nil
}

func (km *KeyManager) LoadKeyFromFile(path string) ([]byte, error) {
	keyHex, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read the file at path %s: %v", path, err)
	}

	key, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex coded key file : %v", err)
	}

	if len(key) != km.keySize {
		return nil, fmt.Errorf("invalid key size: expected %v, but got %v", km.keySize, len(key))
	}

	return key, nil

}
