package hashing

import (
	"crypto/sha1"
	"io"
)

type SHA1Hasher struct{}

func NewSHA1Hasher() Hasher {
	return &SHA1Hasher{}
}

func (h *SHA1Hasher) Hash(reader io.Reader) (string, error) {
	return hashfn(reader, sha1.New())
}
