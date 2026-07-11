package compress

import (
	"io"

	"github.com/pierrec/lz4/v4"
)

// lz4Codec implements Codec using github.com/pierrec/lz4/v4.
type lz4Codec struct{}

func (lz4Codec) ID() CompressionID { return CompressionLZ4 }

func (lz4Codec) NewWriter(dst io.Writer) (io.WriteCloser, error) {
	return lz4.NewWriter(dst), nil
}

func (lz4Codec) NewReader(src io.Reader) (io.ReadCloser, error) {
	return lz4ReadCloser{lz4.NewReader(src)}, nil
}

// lz4ReadCloser adapts *lz4.Reader, which does not implement io.Closer
// upstream, to io.ReadCloser with a no-op Close.
type lz4ReadCloser struct {
	*lz4.Reader
}

func (lz4ReadCloser) Close() error { return nil }
