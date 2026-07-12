package compress

import (
	"io"

	"github.com/dsnet/compress/bzip2"
)

// bzip2Codec implements Codec using github.com/dsnet/compress/bzip2.
type bzip2Codec struct{}

func (bzip2Codec) ID() CompressionID { return CompressionBzip2 }

func (bzip2Codec) NewWriter(dst io.Writer) (io.WriteCloser, error) {
	return bzip2.NewWriter(dst, &bzip2.WriterConfig{})
}

func (bzip2Codec) NewReader(src io.Reader) (io.ReadCloser, error) {
	return bzip2.NewReader(src, &bzip2.ReaderConfig{})
}
