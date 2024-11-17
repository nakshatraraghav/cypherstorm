package encryption

import (
	"fmt"
	"io"

	"github.com/nakshatraraghav/cypherstorm/constants"
)

type Encryptor interface {
	Encrypt(reader io.Reader, writer io.Writer, key []byte) error
	Decrypt(reader io.Reader, writer io.Writer, key []byte) error
}

func NewEncryptor(algorithm string) (Encryptor, error) {
	switch algorithm {
	case constants.AES_256_GCM:
		return NewAesGcmEncryptor(), nil
	case constants.XCHACHA20_POLY1305:
		return NewXChaCha20Poly1305Encryptor(), nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}
