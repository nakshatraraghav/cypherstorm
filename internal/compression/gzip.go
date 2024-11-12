package compression

import (
	"compress/gzip"
	"io"
)

type GzipCompressor struct{}

func newGzipCompressor() Compressor {
	return &GzipCompressor{}
}

func (GzipCompressor) Compress(reader io.Reader, writer io.Writer) error {
	encoder := gzip.NewWriter(writer)
	defer encoder.Close()
	_, err := io.Copy(encoder, reader)
	return err
}

func (GzipCompressor) Decompress(reader io.Reader, writer io.Writer) error {
	decoder, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer decoder.Close()
	_, err = io.Copy(writer, decoder)
	return err
}
