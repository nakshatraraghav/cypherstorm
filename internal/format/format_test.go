package format

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func validPasswordHeader() Header {
	var salt [SaltSize]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	return Header{
		Version:           Version1,
		CipherID:          CipherAES256GCM,
		CodecID:           CodecGzip,
		KDFID:             KDFArgon2id,
		Argon2Time:        3,
		Argon2MemoryKiB:   64 * 1024,
		Argon2Parallelism: 4,
		Argon2KeyLength:   32,
		Salt:              salt,
		RecordSize:        64 * 1024,
	}
}

func TestHeaderEncodeDecodeRoundTrip(t *testing.T) {
	passwordHeader := validPasswordHeader()
	rawHeader := passwordHeader
	rawHeader.KDFID = KDFRaw
	rawHeader.Argon2Time = 0
	rawHeader.Argon2MemoryKiB = 0
	rawHeader.Argon2Parallelism = 0
	rawHeader.Argon2KeyLength = 0

	for _, test := range []struct {
		name   string
		header Header
	}{
		{name: "password", header: passwordHeader},
		{name: "raw key", header: rawHeader},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.header.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(encoded) != HeaderLenV1 {
				t.Fatalf("encoded header length = %d, want %d", len(encoded), HeaderLenV1)
			}
			decoded, err := DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader: %v", err)
			}
			if *decoded != test.header {
				t.Fatalf("decoded header mismatch:\n got: %#v\nwant: %#v", *decoded, test.header)
			}
		})
	}
}

func TestHeaderEncodeRejectsInvalidFields(t *testing.T) {
	base := validPasswordHeader()
	tests := []struct {
		name   string
		mutate func(*Header)
		want   string
	}{
		{name: "version", mutate: func(h *Header) { h.Version++ }, want: "unsupported header version"},
		{name: "cipher", mutate: func(h *Header) { h.CipherID = CipherUnknown }, want: "invalid cipher id"},
		{name: "codec", mutate: func(h *Header) { h.CodecID = CodecUnknown }, want: "invalid codec id"},
		{name: "kdf", mutate: func(h *Header) { h.KDFID = 99 }, want: "invalid kdf id"},
		{name: "record size", mutate: func(h *Header) { h.RecordSize = 0 }, want: "record size must be nonzero"},
		{name: "record size above maximum", mutate: func(h *Header) { h.RecordSize = MaxRecordSize + 1 }, want: "exceeds maximum"},
		{name: "missing argon2 parameter", mutate: func(h *Header) { h.Argon2MemoryKiB = 0 }, want: "requires nonzero parameters"},
		{name: "raw kdf with argon2 parameters", mutate: func(h *Header) { h.KDFID = KDFRaw }, want: "must not carry argon2 parameters"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := base
			test.mutate(&header)
			_, err := header.Encode()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestDecodeHeaderRejectsMalformedBoundaries(t *testing.T) {
	header := validPasswordHeader()
	encoded, err := header.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tests := []struct {
		name  string
		input func() []byte
		want  string
	}{
		{name: "truncated prefix", input: func() []byte { return append([]byte(nil), encoded[:FixedPrefixLen-1]...) }, want: "header truncated"},
		{name: "bad magic", input: func() []byte { b := append([]byte(nil), encoded...); b[0] ^= 0xff; return b }, want: "bad magic"},
		{name: "unsupported version", input: func() []byte { b := append([]byte(nil), encoded...); b[8]++; return b }, want: "unsupported header version"},
		{name: "wrong v1 length", input: func() []byte {
			b := append([]byte(nil), encoded...)
			binary.BigEndian.PutUint16(b[9:11], HeaderLenV1+1)
			return b
		}, want: "version 1 header length"},
		{name: "oversized declared length", input: func() []byte {
			b := append([]byte(nil), encoded[:FixedPrefixLen]...)
			binary.BigEndian.PutUint16(b[9:11], MaxHeaderLen+1)
			return b
		}, want: "exceeds maximum"},
		{name: "unknown cipher", input: func() []byte { b := append([]byte(nil), encoded...); b[11] = 99; return b }, want: "unknown cipher id"},
		{name: "unknown codec", input: func() []byte { b := append([]byte(nil), encoded...); b[12] = 99; return b }, want: "unknown codec id"},
		{name: "unknown kdf", input: func() []byte { b := append([]byte(nil), encoded...); b[13] = 99; return b }, want: "unknown kdf id"},
		{name: "zero record size", input: func() []byte { b := append([]byte(nil), encoded...); binary.BigEndian.PutUint32(b[56:60], 0); return b }, want: "record size must be nonzero"},
		{name: "record size above maximum", input: func() []byte {
			b := append([]byte(nil), encoded...)
			binary.BigEndian.PutUint32(b[56:60], MaxRecordSize+1)
			return b
		}, want: "exceeds maximum"},
		{name: "zero argon2 parameter", input: func() []byte { b := append([]byte(nil), encoded...); binary.BigEndian.PutUint32(b[14:18], 0); return b }, want: "requires nonzero parameters"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeHeader(test.input())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestPeekHeaderLengthBoundsBeforeAllocation(t *testing.T) {
	prefix := make([]byte, FixedPrefixLen)
	copy(prefix, Magic[:])
	binary.BigEndian.PutUint16(prefix[9:11], MaxHeaderLen+1)

	_, err := PeekHeaderLength(prefix)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected maximum-header-length error, got %v", err)
	}

	binary.BigEndian.PutUint16(prefix[9:11], FixedPrefixLen-1)
	_, err = PeekHeaderLength(prefix)
	if err == nil || !strings.Contains(err.Error(), "smaller than fixed prefix") {
		t.Fatalf("expected minimum-header-length error, got %v", err)
	}

	binary.BigEndian.PutUint16(prefix[9:11], HeaderLenV1)
	got, err := PeekHeaderLength(prefix)
	if err != nil {
		t.Fatalf("PeekHeaderLength: %v", err)
	}
	if got != HeaderLenV1 {
		t.Fatalf("header length = %d, want %d", got, HeaderLenV1)
	}
}

func TestAssociatedDataBindsHeaderTypeAndIndex(t *testing.T) {
	header := bytes.Repeat([]byte{0x42}, HeaderLenV1)
	first := AssociatedData(header, RecordTypeData, 7)
	second := AssociatedData(header, RecordTypeFinal, 7)
	third := AssociatedData(header, RecordTypeData, 8)
	if bytes.Equal(first, second) || bytes.Equal(first, third) {
		t.Fatal("associated data does not distinguish record type and index")
	}
}
