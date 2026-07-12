package compress

import (
	"compress/gzip"
	"io"
)

// gzipCodec implements Codec using the standard library compress/gzip.
type gzipCodec struct{}

func (gzipCodec) ID() CompressionID { return CompressionGzip }

func (gzipCodec) NewWriter(dst io.Writer) (io.WriteCloser, error) {
	return gzip.NewWriter(dst), nil
}

func (gzipCodec) NewReader(src io.Reader) (io.ReadCloser, error) {
	return gzip.NewReader(src)
}
