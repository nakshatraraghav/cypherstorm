package hashing

import (
	"crypto/sha256"
	"io"
)

type SHA256Hasher struct{}

func NewSHA256Hasher() Hasher {
	return &SHA256Hasher{}
}

func (h *SHA256Hasher) Hash(reader io.Reader) (string, error) {
	return hashfn(reader, sha256.New())
}
