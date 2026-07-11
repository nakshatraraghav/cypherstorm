package compress_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

func roundTrip(t *testing.T, codec compress.Codec, data []byte) []byte {
	t.Helper()

	var compressed bytes.Buffer
	w, err := codec.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("%s: NewWriter: %v", codec.ID(), err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("%s: Write: %v", codec.ID(), err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("%s: Close: %v", codec.ID(), err)
	}

	r, err := codec.NewReader(&compressed)
	if err != nil {
		t.Fatalf("%s: NewReader: %v", codec.ID(), err)
	}
	defer r.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s: ReadAll: %v", codec.ID(), err)
	}
	return out
}

func TestAllCodecsRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 70 * 1024}

	for _, codec := range compress.AllCodecs() {
		codec := codec
		t.Run(string(codec.ID()), func(t *testing.T) {
			for _, size := range sizes {
				data := testutil.RandomBytes(t, size)
				out := roundTrip(t, codec, data)
				if !bytes.Equal(data, out) {
					t.Fatalf("%s: round trip mismatch at size %d: got %d bytes, want %d bytes",
						codec.ID(), size, len(out), len(data))
				}
			}
		})
	}
}

func TestAllCodecsDeterministicOrder(t *testing.T) {
	want := []compress.CompressionID{
		compress.CompressionGzip,
		compress.CompressionZstd,
		compress.CompressionLZ4,
		compress.CompressionBzip2,
		compress.CompressionLZMA,
	}

	for i := range 5 {
		codecs := compress.AllCodecs()
		if len(codecs) != len(want) {
			t.Fatalf("AllCodecs() returned %d codecs, want %d", len(codecs), len(want))
		}
		for j, codec := range codecs {
			if codec.ID() != want[j] {
				t.Fatalf("AllCodecs()[%d] = %q, want %q (iteration %d)", j, codec.ID(), want[j], i)
			}
		}
	}
}

func TestNewCodec(t *testing.T) {
	for _, id := range []compress.CompressionID{
		compress.CompressionGzip,
		compress.CompressionZstd,
		compress.CompressionLZ4,
		compress.CompressionBzip2,
		compress.CompressionLZMA,
	} {
		codec, err := compress.NewCodec(id)
		if err != nil {
			t.Fatalf("NewCodec(%q): unexpected error: %v", id, err)
		}
		if codec.ID() != id {
			t.Fatalf("NewCodec(%q).ID() = %q", id, codec.ID())
		}
	}

	if _, err := compress.NewCodec(compress.CompressionID("not-a-codec")); err == nil {
		t.Fatal("NewCodec(unknown id): expected error, got nil")
	}
}

func TestGzipReaderRejectsCorruptInput(t *testing.T) {
	codec, err := compress.NewCodec(compress.CompressionGzip)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	var compressed bytes.Buffer
	w, err := codec.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(testutil.RandomBytes(t, 4096)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	truncated := compressed.Bytes()[:compressed.Len()-16]
	r, err := codec.NewReader(bytes.NewReader(truncated))
	if err != nil {
		// A header-level rejection is also an acceptable failure mode.
		return
	}
	defer r.Close()

	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("gzip: expected error reading truncated stream, got nil")
	}
}

func TestZstdReaderRejectsCorruptInput(t *testing.T) {
	codec, err := compress.NewCodec(compress.CompressionZstd)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	var compressed bytes.Buffer
	w, err := codec.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(testutil.RandomBytes(t, 4096)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	garbage := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	r, err := codec.NewReader(bytes.NewReader(garbage))
	if err != nil {
		// Rejecting the malformed frame header outright is also acceptable.
		return
	}
	defer r.Close()

	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("zstd: expected error reading corrupt stream, got nil")
	}
}
