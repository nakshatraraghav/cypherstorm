package compression

import "io"

type Compressor interface {
	Compress(reader io.Reader, writer io.Writer) error
	Decompress(reader io.Reader, writer io.Writer) error
}

type CompressionConfig struct {
	Algorithm string
	Level     int
}
