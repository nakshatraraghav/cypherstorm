package crypto

import (
	"crypto/cipher"
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/format"
)

// sealRecord derives the deterministic nonce for (id, index), builds the
// AAD binding headerBytes||recordType||recordIndex, and returns the sealed
// ciphertext for plaintext.
func sealRecord(aead cipher.AEAD, id CipherID, headerBytes []byte, recordType format.RecordType, index uint64, plaintext []byte) ([]byte, error) {
	nonce, err := deriveNonce(id, index, aead.NonceSize())
	if err != nil {
		return nil, err
	}
	aad := format.AssociatedData(headerBytes, recordType, index)
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// openRecord is the inverse of sealRecord: it rebuilds the same nonce and
// AAD and authenticates+decrypts ciphertext.
func openRecord(aead cipher.AEAD, id CipherID, headerBytes []byte, recordType format.RecordType, index uint64, ciphertext []byte) ([]byte, error) {
	nonce, err := deriveNonce(id, index, aead.NonceSize())
	if err != nil {
		return nil, err
	}
	aad := format.AssociatedData(headerBytes, recordType, index)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	return plaintext, nil
}
