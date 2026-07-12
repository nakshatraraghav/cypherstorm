// Package compress provides streaming compression codec strategies behind a
// shared Codec interface, plus a deterministic factory and registry used by
// the benchmark and protect/restore pipelines.
//
// Supported codecs, selected by CompressionID:
//
//	CompressionGzip  = "gzip"   (compress/gzip, stdlib)
//	CompressionZstd  = "zstd"   (github.com/klauspost/compress/zstd)
//	CompressionLZ4   = "lz4"    (github.com/pierrec/lz4/v4)
//	CompressionBzip2 = "bzip2"  (github.com/dsnet/compress/bzip2)
//	CompressionLZMA  = "lzma"   (github.com/ulikunitz/xz)
//
// Every Codec is purely streaming: NewWriter/NewReader never buffer an
// entire payload in memory, and every writer's Close error is the
// underlying encoder's finalization error, propagated unmodified — never
// swallowed by this package.
//
// Use NewCodec to look up a single codec by ID, or AllCodecs for the fixed,
// deterministic ordering (gzip, zstd, lz4, bzip2, lzma) required by
// benchmark loops that must not depend on map iteration order.
package compress

import (
	"fmt"
	"io"
)

// CompressionID identifies a registered compression codec.
type CompressionID string

const (
	CompressionGzip  CompressionID = "gzip"
	CompressionBzip2 CompressionID = "bzip2"
	CompressionLZ4   CompressionID = "lz4"
	CompressionLZMA  CompressionID = "lzma"
	CompressionZstd  CompressionID = "zstd"
)

// Decoder limits bound per-stream working memory before archive extraction
// applies its independent output-size limits. zstd and LZMA are configured
// explicitly; gzip, bzip2, and LZ4 have bounded decoder state in their
// upstream streaming implementations.
const (
	maxDecoderMemory     uint64 = 64 << 20
	maxDecoderDictionary int    = 64 << 20
)

// Codec is a streaming compression strategy: NewWriter wraps an io.Writer
// to compress data written to it, and NewReader wraps an io.Reader to
// decompress data read from it. Implementations must stream — never buffer
// a whole payload in memory — and must never swallow the underlying
// encoder's finalization error from the returned writer's Close method.
type Codec interface {
	// ID returns the codec's registered CompressionID.
	ID() CompressionID

	// NewWriter returns a streaming compressor writing compressed output
	// to dst. The caller must call Close on the returned writer to flush
	// and finalize the stream; its error is the underlying encoder's
	// finalization error.
	NewWriter(dst io.Writer) (io.WriteCloser, error)

	// NewReader returns a streaming decompressor reading compressed input
	// from src.
	NewReader(src io.Reader) (io.ReadCloser, error)
}

// NewCodec returns the Codec registered for id, or an error if id is not a
// recognized CompressionID.
func NewCodec(id CompressionID) (Codec, error) {
	switch id {
	case CompressionGzip:
		return gzipCodec{}, nil
	case CompressionZstd:
		return zstdCodec{}, nil
	case CompressionLZ4:
		return lz4Codec{}, nil
	case CompressionBzip2:
		return bzip2Codec{}, nil
	case CompressionLZMA:
		return lzmaCodec{}, nil
	default:
		return nil, fmt.Errorf("compress: unsupported codec id %q", id)
	}
}

// AllCodecs returns every registered Codec in a fixed, deterministic order
// (gzip, zstd, lz4, bzip2, lzma). Callers building benchmark combinations or
// any other algorithm-registry loop must use this instead of iterating a
// map, which Go does not guarantee to visit in a stable order.
func AllCodecs() []Codec {
	return []Codec{
		gzipCodec{},
		zstdCodec{},
		lz4Codec{},
		bzip2Codec{},
		lzmaCodec{},
	}
}
