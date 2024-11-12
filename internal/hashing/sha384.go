package hashing

import (
	"crypto/sha512"
	"io"
)

type SHA384Hasher struct{}

func NewSHA384Hasher() Hasher {
	return &SHA384Hasher{}
}

func (h *SHA384Hasher) Hash(reader io.Reader) (string, error) {
	return hashfn(reader, sha512.New384())
}
