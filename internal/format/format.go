// Package format encodes and decodes the CypherStorm v1 protected-file
// container: a fixed-size authenticated header followed by a sequence of
// length-prefixed, sequence-numbered records.
//
// This package owns wire-level framing only: header field layout, bounds
// checking on untrusted input, and the associated-data construction used to
// bind header bytes into every record's AEAD authentication. It performs no
// cryptography itself (no AEAD, no KDF) and has no dependency on any cipher
// or compression package, so it can be safely imported by internal/crypto
// without a cycle. Callers (internal/crypto) are responsible for actually
// sealing/opening record ciphertext and choosing nonces; this package only
// defines what bytes go on the wire and validates them.
//
// Wire layout (all multi-byte integers big-endian):
//
//	Header (fixed HeaderLen bytes):
//	  0   8   Magic             constant "CYPHRSTM"
//	  8   1   Version           format version (1)
//	  9   2   HeaderLength      uint16, total header length including this field
//	  11  1   CipherID          uint8 enum
//	  12  1   CodecID           uint8 enum
//	  13  1   KDFID             uint8 enum
//	  14  4   Argon2Time        uint32 (0 when KDFID != KDFArgon2id)
//	  18  4   Argon2MemoryKiB   uint32 (0 when KDFID != KDFArgon2id)
//	  22  1   Argon2Parallelism uint8  (0 when KDFID != KDFArgon2id)
//	  23  1   Argon2KeyLength   uint8  (0 when KDFID != KDFArgon2id)
//	  24  32  Salt              random per-file salt, always present
//	  56  4   RecordSize        uint32, max plaintext bytes per data record
//	  ---
//	  60      HeaderLen for v1
//
//	Record (repeated until a Final record is consumed):
//	  0   1   RecordType    1=Data, 2=Final
//	  1   8   RecordIndex   uint64, monotonic, starts at 0, contiguous
//	  9   4   CipherLen     uint32, length of the following ciphertext
//	  13  N   Ciphertext    AEAD-sealed bytes (plaintext + AEAD overhead)
//
// The associated data authenticated with every record is
// HeaderBytes || RecordType || RecordIndex (see AssociatedData), so any
// header tampering causes every record to fail authentication even though
// the header itself carries no separate MAC.
package format

import (
	"encoding/binary"
	"fmt"
)

// Magic is the fixed, version-independent prefix identifying a CypherStorm
// protected file.
var Magic = [8]byte{'C', 'Y', 'P', 'H', 'R', 'S', 'T', 'M'}

// Version1 is the only supported format version.
const Version1 uint8 = 1

// SaltSize is the fixed length of the per-file random salt.
const SaltSize = 32

// HeaderLenV1 is the total encoded size of a version-1 header.
const HeaderLenV1 = 60

// MaxHeaderLen bounds header parsing before any allocation, independent of
// the version-specific fixed size, so a corrupt/hostile HeaderLength field
// can never trigger an oversized read.
const MaxHeaderLen = 4096

// MaxRecordSize bounds plaintext record buffers and ensures ciphertext
// records remain well below MaxCipherLen after AEAD overhead.
const MaxRecordSize uint32 = 16 * 1024 * 1024

// CipherID is the wire-level cipher-suite identifier stored in the header.
// It is intentionally decoupled from internal/crypto's human-facing string
// CipherID; internal/crypto owns the translation between the two.
type CipherID uint8

const (
	CipherUnknown           CipherID = 0
	CipherAES256GCM         CipherID = 1
	CipherXChaCha20Poly1305 CipherID = 2
)

func (c CipherID) valid() bool {
	return c == CipherAES256GCM || c == CipherXChaCha20Poly1305
}

// CodecID is the wire-level compression codec identifier stored in the
// header, decoupled from internal/compress's human-facing string ID.
type CodecID uint8

const (
	CodecUnknown CodecID = 0
	CodecGzip    CodecID = 1
	CodecZstd    CodecID = 2
	CodecLZ4     CodecID = 3
	CodecBzip2   CodecID = 4
	CodecLZMA    CodecID = 5
)

func (c CodecID) valid() bool {
	switch c {
	case CodecGzip, CodecZstd, CodecLZ4, CodecBzip2, CodecLZMA:
		return true
	default:
		return false
	}
}

// KDFID identifies how the header's Argon2 parameter fields should be
// interpreted.
type KDFID uint8

const (
	// KDFRaw means the credential source supplied key material directly;
	// the Argon2 parameter fields are zero and unused.
	KDFRaw KDFID = 0
	// KDFArgon2id means the credential source was a password and the
	// Argon2 parameter fields must be used to reproduce the master key.
	KDFArgon2id KDFID = 1
)

func (k KDFID) valid() bool {
	return k == KDFRaw || k == KDFArgon2id
}

// Header is the fully decoded, validated v1 protected-file header.
type Header struct {
	Version           uint8
	CipherID          CipherID
	CodecID           CodecID
	KDFID             KDFID
	Argon2Time        uint32
	Argon2MemoryKiB   uint32
	Argon2Parallelism uint8
	Argon2KeyLength   uint8
	Salt              [SaltSize]byte
	RecordSize        uint32
}

// Encode serializes h into its canonical v1 wire form.
func (h *Header) Encode() ([]byte, error) {
	if h.Version != Version1 {
		return nil, fmt.Errorf("format: unsupported header version %d", h.Version)
	}
	if !h.CipherID.valid() {
		return nil, fmt.Errorf("format: invalid cipher id %d", h.CipherID)
	}
	if !h.CodecID.valid() {
		return nil, fmt.Errorf("format: invalid codec id %d", h.CodecID)
	}
	if !h.KDFID.valid() {
		return nil, fmt.Errorf("format: invalid kdf id %d", h.KDFID)
	}
	if h.RecordSize == 0 {
		return nil, fmt.Errorf("format: record size must be nonzero")
	}
	if h.RecordSize > MaxRecordSize {
		return nil, fmt.Errorf("format: record size %d exceeds maximum %d", h.RecordSize, MaxRecordSize)
	}
	if h.KDFID == KDFArgon2id {
		if h.Argon2Time == 0 || h.Argon2MemoryKiB == 0 || h.Argon2Parallelism == 0 || h.Argon2KeyLength == 0 {
			return nil, fmt.Errorf("format: argon2id kdf requires nonzero parameters")
		}
	} else {
		if h.Argon2Time != 0 || h.Argon2MemoryKiB != 0 || h.Argon2Parallelism != 0 || h.Argon2KeyLength != 0 {
			return nil, fmt.Errorf("format: raw kdf must not carry argon2 parameters")
		}
	}

	buf := make([]byte, HeaderLenV1)
	copy(buf[0:8], Magic[:])
	buf[8] = h.Version
	binary.BigEndian.PutUint16(buf[9:11], HeaderLenV1)
	buf[11] = byte(h.CipherID)
	buf[12] = byte(h.CodecID)
	buf[13] = byte(h.KDFID)
	binary.BigEndian.PutUint32(buf[14:18], h.Argon2Time)
	binary.BigEndian.PutUint32(buf[18:22], h.Argon2MemoryKiB)
	buf[22] = h.Argon2Parallelism
	buf[23] = h.Argon2KeyLength
	copy(buf[24:24+SaltSize], h.Salt[:])
	binary.BigEndian.PutUint32(buf[56:60], h.RecordSize)

	return buf, nil
}

// DecodeHeader parses and strictly validates a header from buf, which must
// contain at least the encoded header bytes (trailing bytes are ignored by
// this function; callers read exactly HeaderLength bytes using the fixed
// prefix below before calling this).
//
// All bounds/ID/parameter validation happens before any field is trusted,
// per the fail-closed requirement: unknown versions/IDs are rejected here.
func DecodeHeader(buf []byte) (*Header, error) {
	const fixedPrefix = 11 // Magic + Version + HeaderLength

	if len(buf) < fixedPrefix {
		return nil, fmt.Errorf("format: header truncated: need at least %d bytes, got %d", fixedPrefix, len(buf))
	}
	if [8]byte(buf[0:8]) != Magic {
		return nil, fmt.Errorf("format: bad magic")
	}

	version := buf[8]
	headerLen := binary.BigEndian.Uint16(buf[9:11])

	if int(headerLen) > MaxHeaderLen {
		return nil, fmt.Errorf("format: declared header length %d exceeds maximum %d", headerLen, MaxHeaderLen)
	}
	if version != Version1 {
		return nil, fmt.Errorf("format: unsupported header version %d", version)
	}
	if headerLen != HeaderLenV1 {
		return nil, fmt.Errorf("format: version 1 header length must be %d, got %d", HeaderLenV1, headerLen)
	}
	if len(buf) < int(headerLen) {
		return nil, fmt.Errorf("format: header truncated: need %d bytes, got %d", headerLen, len(buf))
	}

	h := &Header{
		Version:           version,
		CipherID:          CipherID(buf[11]),
		CodecID:           CodecID(buf[12]),
		KDFID:             KDFID(buf[13]),
		Argon2Time:        binary.BigEndian.Uint32(buf[14:18]),
		Argon2MemoryKiB:   binary.BigEndian.Uint32(buf[18:22]),
		Argon2Parallelism: buf[22],
		Argon2KeyLength:   buf[23],
		RecordSize:        binary.BigEndian.Uint32(buf[56:60]),
	}
	copy(h.Salt[:], buf[24:24+SaltSize])

	if !h.CipherID.valid() {
		return nil, fmt.Errorf("format: unknown cipher id %d", h.CipherID)
	}
	if !h.CodecID.valid() {
		return nil, fmt.Errorf("format: unknown codec id %d", h.CodecID)
	}
	if !h.KDFID.valid() {
		return nil, fmt.Errorf("format: unknown kdf id %d", h.KDFID)
	}
	if h.RecordSize == 0 {
		return nil, fmt.Errorf("format: record size must be nonzero")
	}
	if h.RecordSize > MaxRecordSize {
		return nil, fmt.Errorf("format: record size %d exceeds maximum %d", h.RecordSize, MaxRecordSize)
	}
	if h.KDFID == KDFArgon2id {
		if h.Argon2Time == 0 || h.Argon2MemoryKiB == 0 || h.Argon2Parallelism == 0 || h.Argon2KeyLength == 0 {
			return nil, fmt.Errorf("format: argon2id kdf requires nonzero parameters")
		}
	} else {
		if h.Argon2Time != 0 || h.Argon2MemoryKiB != 0 || h.Argon2Parallelism != 0 || h.Argon2KeyLength != 0 {
			return nil, fmt.Errorf("format: raw kdf must not carry argon2 parameters")
		}
	}

	return h, nil
}

// FixedPrefixLen is the number of bytes a streaming reader must read before
// it knows the full header length: Magic + Version + HeaderLength.
const FixedPrefixLen = 11

// PeekHeaderLength reads only the fixed prefix of buf and returns the
// declared total header length, strictly bounded by MaxHeaderLen, without
// interpreting or trusting any other field. Intended for streaming readers
// that need to know how many more bytes to read before calling DecodeHeader.
func PeekHeaderLength(prefix []byte) (uint16, error) {
	if len(prefix) < FixedPrefixLen {
		return 0, fmt.Errorf("format: header prefix truncated: need %d bytes, got %d", FixedPrefixLen, len(prefix))
	}
	if [8]byte(prefix[0:8]) != Magic {
		return 0, fmt.Errorf("format: bad magic")
	}
	headerLen := binary.BigEndian.Uint16(prefix[9:11])
	if int(headerLen) > MaxHeaderLen {
		return 0, fmt.Errorf("format: declared header length %d exceeds maximum %d", headerLen, MaxHeaderLen)
	}
	if int(headerLen) < FixedPrefixLen {
		return 0, fmt.Errorf("format: declared header length %d smaller than fixed prefix %d", headerLen, FixedPrefixLen)
	}
	return headerLen, nil
}
