package compress

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// zstdCodec implements Codec using github.com/klauspost/compress/zstd.
type zstdCodec struct{}

func (zstdCodec) ID() CompressionID { return CompressionZstd }

func (zstdCodec) NewWriter(dst io.Writer) (io.WriteCloser, error) {
	return zstd.NewWriter(dst)
}

func (zstdCodec) NewReader(src io.Reader) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(src)
	if err != nil {
		return nil, err
	}
	return zstdReadCloser{decoder}, nil
}

// zstdReadCloser adapts *zstd.Decoder — whose Close method returns no error
// — to io.ReadCloser. There is no finalization error to swallow: the
// upstream Close signature simply has none.
type zstdReadCloser struct {
	*zstd.Decoder
}

func (z zstdReadCloser) Close() error {
	z.Decoder.Close()
	return nil
}
