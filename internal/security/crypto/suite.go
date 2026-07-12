// Package crypto implements CypherStorm's registered AEAD cipher suites.
//
// CipherSuite is the algorithm-extension seam: adding a new AEAD cipher
// means implementing this interface and registering it in NewCipherSuite.
// It provides AEAD construction only; the canonical container package owns
// protected-file framing and authenticated record construction.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherID is the human-facing, CLI/config-facing cipher identifier. The
// canonical container serializes it as its stable textual wire identifier.
type CipherID string

const (
	AES256GCM         CipherID = "aes-256-gcm"
	XChaCha20Poly1305 CipherID = "xchacha20poly1305"
)

// CipherSuite is the retained strategy interface for AEAD cipher
// algorithms. Concrete implementations are unexported; obtain one through
// NewCipherSuite.
type CipherSuite interface {
	ID() CipherID
	KeySize() int
	NonceSize() int
	NewAEAD(key []byte) (cipher.AEAD, error)
}

// AllCipherIDs returns every registered cipher suite ID in a fixed,
// deterministic order (never derived from map iteration).
func AllCipherIDs() []CipherID {
	return []CipherID{AES256GCM, XChaCha20Poly1305}
}

// NewCipherSuite returns the strategy for id, or an error for any ID not
// registered here (fail closed on unknown/unsupported algorithms).
func NewCipherSuite(id CipherID) (CipherSuite, error) {
	switch id {
	case AES256GCM:
		return aesGCMSuite{}, nil
	case XChaCha20Poly1305:
		return xchacha20Poly1305Suite{}, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported cipher suite %q", id)
	}
}

type aesGCMSuite struct{}

func (aesGCMSuite) ID() CipherID   { return AES256GCM }
func (aesGCMSuite) KeySize() int   { return 32 }
func (aesGCMSuite) NonceSize() int { return 12 }

func (aesGCMSuite) NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: aes-256-gcm requires a 32-byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating gcm: %w", err)
	}
	return gcm, nil
}

type xchacha20Poly1305Suite struct{}

func (xchacha20Poly1305Suite) ID() CipherID   { return XChaCha20Poly1305 }
func (xchacha20Poly1305Suite) KeySize() int   { return chacha20poly1305.KeySize }
func (xchacha20Poly1305Suite) NonceSize() int { return chacha20poly1305.NonceSizeX }

func (xchacha20Poly1305Suite) NewAEAD(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating xchacha20-poly1305: %w", err)
	}
	return aead, nil
}
