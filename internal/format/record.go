package format

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// RecordType distinguishes a data record carrying ciphertext of caller
// plaintext from the final record committing total counts.
type RecordType uint8

const (
	RecordTypeUnknown RecordType = 0
	RecordTypeData    RecordType = 1
	RecordTypeFinal   RecordType = 2
)

func (t RecordType) valid() bool {
	return t == RecordTypeData || t == RecordTypeFinal
}

// RecordHeaderLen is the fixed size of a record's framing prefix, before
// the ciphertext bytes: RecordType(1) + RecordIndex(8) + CipherLen(4).
const RecordHeaderLen = 13

// MaxCipherLen bounds the ciphertext length field before allocation. It is
// deliberately generous (records are additionally bounded by the header's
// RecordSize + AEAD overhead by the crypto engine) but prevents a hostile
// 32-bit length field from requesting a multi-gigabyte allocation outright.
const MaxCipherLen = 64 * 1024 * 1024

// RecordHeader is the decoded framing prefix of one on-wire record.
type RecordHeader struct {
	Type      RecordType
	Index     uint64
	CipherLen uint32
}

// EncodeRecordHeader serializes a record framing prefix. It does not write
// the ciphertext itself; callers write that immediately after.
func EncodeRecordHeader(h RecordHeader) ([]byte, error) {
	if !h.Type.valid() {
		return nil, fmt.Errorf("format: invalid record type %d", h.Type)
	}
	buf := make([]byte, RecordHeaderLen)
	buf[0] = byte(h.Type)
	binary.BigEndian.PutUint64(buf[1:9], h.Index)
	binary.BigEndian.PutUint32(buf[9:13], h.CipherLen)
	return buf, nil
}

// WriteRecord writes one full record (framing prefix + ciphertext) to w,
// verifying every write's length against the intended length so a short
// write is never silently treated as success.
func WriteRecord(w io.Writer, h RecordHeader, ciphertext []byte) error {
	h.CipherLen = uint32(len(ciphertext))

	hdr, err := EncodeRecordHeader(h)
	if err != nil {
		return err
	}

	if n, err := w.Write(hdr); err != nil {
		return fmt.Errorf("format: writing record header: %w", err)
	} else if n != len(hdr) {
		return fmt.Errorf("format: writing record header: %w", io.ErrShortWrite)
	}

	if n, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("format: writing record ciphertext: %w", err)
	} else if n != len(ciphertext) {
		return fmt.Errorf("format: writing record ciphertext: %w", io.ErrShortWrite)
	}

	return nil
}

// ReadRecordHeader reads and validates one record's framing prefix from r,
// bounding CipherLen before the caller allocates a ciphertext buffer.
// Returns io.EOF (unwrapped) only when zero bytes could be read at the
// start of a record, so callers can distinguish "no more records" from a
// truncated record.
func ReadRecordHeader(r io.Reader) (RecordHeader, error) {
	buf := make([]byte, RecordHeaderLen)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		if n == 0 && err == io.EOF {
			return RecordHeader{}, io.EOF
		}
		return RecordHeader{}, fmt.Errorf("format: reading record header: %w", err)
	}

	h := RecordHeader{
		Type:      RecordType(buf[0]),
		Index:     binary.BigEndian.Uint64(buf[1:9]),
		CipherLen: binary.BigEndian.Uint32(buf[9:13]),
	}
	if !h.Type.valid() {
		return RecordHeader{}, fmt.Errorf("format: unknown record type %d", h.Type)
	}
	if h.CipherLen == 0 {
		return RecordHeader{}, fmt.Errorf("format: zero-length record ciphertext")
	}
	if h.CipherLen > MaxCipherLen {
		return RecordHeader{}, fmt.Errorf("format: record ciphertext length %d exceeds maximum %d", h.CipherLen, MaxCipherLen)
	}

	return h, nil
}

// ReadRecordCiphertext reads exactly h.CipherLen bytes of ciphertext for a
// record header previously returned by ReadRecordHeader, using io.ReadFull
// so framing is never inferred from arbitrary Read boundaries.
func ReadRecordCiphertext(r io.Reader, h RecordHeader) ([]byte, error) {
	buf := make([]byte, h.CipherLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("format: reading record ciphertext: %w", err)
	}
	return buf, nil
}

// AssociatedData builds the AEAD associated data bound to one record:
// headerBytes || recordType || recordIndex (big-endian). Because header
// bytes are included, any header tampering causes every record to fail
// authentication even though the header carries no separate MAC.
func AssociatedData(headerBytes []byte, recordType RecordType, recordIndex uint64) []byte {
	aad := make([]byte, 0, len(headerBytes)+1+8)
	aad = append(aad, headerBytes...)
	aad = append(aad, byte(recordType))
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], recordIndex)
	aad = append(aad, idx[:]...)
	return aad
}

// FinalPayloadLen is the fixed plaintext size of the final record's
// committed-counts payload, before AEAD sealing.
const FinalPayloadLen = 24

// FinalPayload is the authenticated commitment written as the plaintext of
// the final record: total data-record count and total plaintext/ciphertext
// byte counts. Its presence and correctness at EOF prevents truncation,
// record deletion, and record-count manipulation from going undetected.
type FinalPayload struct {
	TotalDataRecords     uint64
	TotalPlaintextBytes  uint64
	TotalCiphertextBytes uint64
}

// Marshal serializes p to its fixed 24-byte wire form.
func (p FinalPayload) Marshal() []byte {
	buf := make([]byte, FinalPayloadLen)
	binary.BigEndian.PutUint64(buf[0:8], p.TotalDataRecords)
	binary.BigEndian.PutUint64(buf[8:16], p.TotalPlaintextBytes)
	binary.BigEndian.PutUint64(buf[16:24], p.TotalCiphertextBytes)
	return buf
}

// UnmarshalFinalPayload parses a final record's plaintext payload, strictly
// rejecting any length other than FinalPayloadLen.
func UnmarshalFinalPayload(buf []byte) (FinalPayload, error) {
	if len(buf) != FinalPayloadLen {
		return FinalPayload{}, fmt.Errorf("format: final record payload must be %d bytes, got %d", FinalPayloadLen, len(buf))
	}
	return FinalPayload{
		TotalDataRecords:     binary.BigEndian.Uint64(buf[0:8]),
		TotalPlaintextBytes:  binary.BigEndian.Uint64(buf[8:16]),
		TotalCiphertextBytes: binary.BigEndian.Uint64(buf[16:24]),
	}, nil
}

// NextIndex returns idx+1, returning an error instead of silently wrapping
// when the monotonic per-file record counter would overflow. In practice
// this requires 2^64 records and is unreachable, but the check is load-
// bearing for the "reject counter overflow" requirement and is exercised
// directly by fuzz/unit tests rather than by driving an actual 2^64 loop.
func NextIndex(idx uint64) (uint64, error) {
	if idx == math.MaxUint64 {
		return 0, fmt.Errorf("format: record counter overflow")
	}
	return idx + 1, nil
}
