package hashing

import (
	"crypto/md5"
	"io"
)

type Md5Hasher struct{}

func NewMd5Hasher() Hasher {
	return &Md5Hasher{}
}

func (h *Md5Hasher) Hash(reader io.Reader) (string, error) {
	return hashfn(reader, md5.New())
}
