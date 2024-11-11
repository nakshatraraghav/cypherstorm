package encryption

import "io"

const (
	AES_256_GCM        string = "aes-256-gcm"
	CHACHA20_POLY1305  string = "chacha20poly1305"
	XCHACHA20_POLY1305 string = "xchacha20poly1305"
	AES_256_CBC        string = "aes-256-cbc"
	TWOFISH            string = "twofish"
)

type Encryptor interface {
	Encrypt(reader io.Reader, writer io.Writer) error
	Decrypt(reader io.Reader, writer io.Writer) error
}
