package compression

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

type ZstdCompressor struct{}

func newZstdCompressor() Compressor {
	return &ZstdCompressor{}
}

func (ZstdCompressor) Compress(reader io.Reader, writer io.Writer) error {
	encoder, err := zstd.NewWriter(writer)
	if err != nil {
		return err
	}
	defer encoder.Close()
	_, err = io.Copy(encoder, reader)
	return err
}

func (ZstdCompressor) Decompress(reader io.Reader, writer io.Writer) error {
	decoder, err := zstd.NewReader(reader)
	if err != nil {
		return err
	}
	defer decoder.Close()
	_, err = io.Copy(writer, decoder)
	return err
}
