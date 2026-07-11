package crypto

import (
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/format"
)

// WireCipherID translates a human-facing CipherID into the compact wire
// enum stored in the format header.
func WireCipherID(id CipherID) (format.CipherID, error) {
	switch id {
	case AES256GCM:
		return format.CipherAES256GCM, nil
	case XChaCha20Poly1305:
		return format.CipherXChaCha20Poly1305, nil
	default:
		return format.CipherUnknown, fmt.Errorf("crypto: unsupported cipher suite %q", id)
	}
}

// FromWireCipherID translates a header wire enum back into the human-facing
// CipherID, failing closed on any value not registered in this package.
func FromWireCipherID(id format.CipherID) (CipherID, error) {
	switch id {
	case format.CipherAES256GCM:
		return AES256GCM, nil
	case format.CipherXChaCha20Poly1305:
		return XChaCha20Poly1305, nil
	default:
		return "", fmt.Errorf("crypto: unknown wire cipher id %d", id)
	}
}
