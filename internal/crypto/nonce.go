package crypto

import (
	"encoding/binary"
	"fmt"
)

// xchachaNoncePrefix is a fixed, public domain-separation constant mixed
// into every XChaCha20-Poly1305 nonce. It is not secret and is identical
// across all files: uniqueness comes from the per-file HKDF-derived key
// (different key per file) combined with the monotonic per-file counter
// (different nonce per record within a file), exactly as specified for the
// "fixed domain/prefix plus the counter" nonce construction.
var xchachaNoncePrefix = [16]byte{'c', 'y', 'p', 'h', 'e', 'r', 's', 't', 'o', 'r', 'm', '/', 'v', '1', '/', 'x'}

// deriveNonce builds the deterministic per-record nonce for suite id from a
// monotonic record counter. AES-GCM uses the full 96-bit nonce as a
// big-endian counter; XChaCha20-Poly1305 uses its 192-bit nonce as a fixed
// 128-bit domain prefix followed by a 64-bit big-endian counter.
func deriveNonce(id CipherID, counter uint64, nonceSize int) ([]byte, error) {
	switch id {
	case AES256GCM:
		if nonceSize != 12 {
			return nil, fmt.Errorf("crypto: aes-256-gcm nonce size must be 12, got %d", nonceSize)
		}
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[4:12], counter)
		return nonce, nil

	case XChaCha20Poly1305:
		if nonceSize != 24 {
			return nil, fmt.Errorf("crypto: xchacha20-poly1305 nonce size must be 24, got %d", nonceSize)
		}
		nonce := make([]byte, 24)
		copy(nonce[0:16], xchachaNoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[16:24], counter)
		return nonce, nil

	default:
		return nil, fmt.Errorf("crypto: unsupported cipher suite %q", id)
	}
}
