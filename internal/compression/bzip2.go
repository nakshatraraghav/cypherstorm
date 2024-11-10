package compression

import (
	"fmt"
	"io"

	"github.com/dsnet/compress/bzip2"
)

type Bzip2Compressor struct{}

func NewBzipCompressor() Compressor {
	return &Bzip2Compressor{}
}

func (Bzip2Compressor) Compress(reader io.Reader, writer io.Writer) error {
	encoder, err := bzip2.NewWriter(writer, &bzip2.WriterConfig{})
	if err != nil {
		return err
	}
	defer encoder.Close()
	_, err = io.Copy(encoder, reader)
	return err
}

func (Bzip2Compressor) Decompress(reader io.Reader, writer io.Writer) error {
	decoder, err := bzip2.NewReader(reader, &bzip2.ReaderConfig{})
	if err != nil {
		return fmt.Errorf("failed to create a instance of Bzip2 Reader: %v", err)
	}
	defer decoder.Close()
	_, err = io.Copy(writer, decoder)
	return err
}
