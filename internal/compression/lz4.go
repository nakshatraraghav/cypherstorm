package compression

import (
	"io"

	"github.com/pierrec/lz4/v4"
)

type Lz4Compressor struct{}

func newLz4Compressor() Compressor {
	return &Lz4Compressor{}
}

func (Lz4Compressor) Compress(reader io.Reader, writer io.Writer) error {
	encoder := lz4.NewWriter(writer)
	defer encoder.Close()
	_, err := io.Copy(encoder, reader)
	return err
}

func (Lz4Compressor) Decompress(reader io.Reader, writer io.Writer) error {
	decoder := lz4.NewReader(reader)
	_, err := io.Copy(writer, decoder)
	return err
}
