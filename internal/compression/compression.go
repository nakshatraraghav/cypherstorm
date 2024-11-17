package compression

import (
	"fmt"
	"io"

	"github.com/nakshatraraghav/cypherstorm/constants"
)

type Compressor interface {
	Compress(reader io.Reader, writer io.Writer) error
	Decompress(reader io.Reader, writer io.Writer) error
}

func NewCompressor(algorithm string) (Compressor, error) {
	switch algorithm {
	case constants.BZIP2:
		return NewBzipCompressor(), nil
	case constants.GZIP:
		return NewGzipCompressor(), nil
	case constants.LZ4:
		return NewLz4Compressor(), nil
	case constants.LZMA:
		return NewLzmaCompressor(), nil
	case constants.ZSTD:
		return NewZstdCompressor(), nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}
