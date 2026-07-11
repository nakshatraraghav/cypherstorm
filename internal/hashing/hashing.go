package hashing

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

// ID identifies a supported cryptographic digest algorithm.
type ID string

const (
	SHA256 ID = "sha256"
	SHA384 ID = "sha384"
	SHA512 ID = "sha512"
)

// AllIDs returns supported algorithms in deterministic order.
func AllIDs() []ID {
	return []ID{SHA256, SHA384, SHA512}
}

func Supported(id ID) bool {
	return id == SHA256 || id == SHA384 || id == SHA512
}

// Digest hashes r with id and returns raw digest bytes. Cancellation is
// checked during the copy; formatting belongs to UI adapters.
func Digest(ctx context.Context, r io.Reader, id ID) ([]byte, error) {
	var h hash.Hash
	switch id {
	case SHA256:
		h = sha256.New()
	case SHA384:
		h = sha512.New384()
	case SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("hashing: unsupported algorithm %q", id)
	}
	if _, err := io.Copy(h, contextReader{ctx: ctx, reader: r}); err != nil {
		return nil, fmt.Errorf("hashing: read input: %w", err)
	}
	return h.Sum(nil), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
