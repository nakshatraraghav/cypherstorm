package hashing

import (
	"crypto/sha512"
	"io"
)

type SHA512Hasher struct{}

func NewSHA512Hasher() Hasher {
	return &SHA512Hasher{}
}

func (h *SHA512Hasher) Hash(reader io.Reader) (string, error) {
	return hashfn(reader, sha512.New())
}
