package hashing

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/nakshatraraghav/cypherstorm/constants"
)

type Hasher interface {
	Hash(reader io.Reader) (string, error)
}

func NewHasher(algorithm string) (Hasher, error) {
	switch algorithm {
	case constants.MD5:
		return NewMd5Hasher(), nil
	case constants.SHA1:
		return NewSHA1Hasher(), nil
	case constants.SHA256:
		return NewSHA256Hasher(), nil
	case constants.SHA384:
		return NewSHA384Hasher(), nil
	case constants.SHA512:
		return NewSHA512Hasher(), nil
	default:
		return nil, fmt.Errorf("unsupported hashing algorithm: %s", algorithm)
	}
}

func hashfn(reader io.Reader, h hash.Hash) (string, error) {
	_, err := io.Copy(h, reader)
	if err != nil {
		return "", fmt.Errorf("failed to hash data: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
