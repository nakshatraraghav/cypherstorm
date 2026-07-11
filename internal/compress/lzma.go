package compress

import (
	"io"

	"github.com/ulikunitz/xz"
)

// lzmaCodec implements Codec using github.com/ulikunitz/xz (LZMA2 inside an
// XZ container), matching the legacy "lzma" codec name.
type lzmaCodec struct{}

func (lzmaCodec) ID() CompressionID { return CompressionLZMA }

func (lzmaCodec) NewWriter(dst io.Writer) (io.WriteCloser, error) {
	return xz.NewWriter(dst)
}

func (lzmaCodec) NewReader(src io.Reader) (io.ReadCloser, error) {
	reader, err := xz.NewReader(src)
	if err != nil {
		return nil, err
	}
	return lzmaReadCloser{reader}, nil
}

// lzmaReadCloser adapts *xz.Reader, which does not implement io.Closer
// upstream, to io.ReadCloser with a no-op Close.
type lzmaReadCloser struct {
	*xz.Reader
}

func (lzmaReadCloser) Close() error { return nil }
