package compression

import (
	"io"

	"github.com/ulikunitz/xz"
)

type LzmaCompressor struct{}

func NewLzmaCompressor() Compressor {
	return &LzmaCompressor{}
}

func (LzmaCompressor) Compress(reader io.Reader, writer io.Writer) error {
	encoder, err := xz.NewWriter(writer)
	if err != nil {
		return err
	}
	defer encoder.Close()
	_, err = io.Copy(encoder, reader)
	return err
}

func (LzmaCompressor) Decompress(reader io.Reader, writer io.Writer) error {
	decoder, err := xz.NewReader(reader)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, decoder)
	return err
}
