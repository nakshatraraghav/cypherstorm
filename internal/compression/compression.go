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
		return newBzipCompressor(), nil
	case constants.GZIP:
		return newGzipCompressor(), nil
	case constants.LZ4:
		return newLz4Compressor(), nil
	case constants.LZMA:
		return newLzmaCompressor(), nil
	case constants.ZSTD:
		return newZstdCompressor(), nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}
