package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/nakshatraraghav/cypherstorm/internal/format"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
)

// EncryptOptions configures one Encrypt call. RecordSize bounds the
// plaintext size of every data record; Argon2 is only consulted (and only
// serialized into the header) when Credential.Kind is kdf.SourcePassword.
type EncryptOptions struct {
	Credential kdf.Credential
	CipherID   CipherID
	CodecID    format.CodecID
	Argon2     kdf.Argon2Params
	RecordSize uint32
}

// Encrypt reads plaintext from r (already run through the caller's chosen
// compression codec, if any) and writes a complete v1 protected-file
// container to w: header, sequence-numbered data records, and an
// authenticated final record committing total counts.
//
// Every record uses a nonce deterministically derived from a monotonic
// counter under a key that is unique to this file (HKDF-derived from the
// credential and a fresh random salt), so no nonce is ever reused across
// records or across files even when the same password or raw key protects
// many files.
func Encrypt(ctx context.Context, r io.Reader, w io.Writer, opts EncryptOptions) error {
	if opts.RecordSize == 0 {
		return fmt.Errorf("crypto: record size must be nonzero")
	}
	if opts.RecordSize > format.MaxRecordSize {
		return fmt.Errorf("crypto: record size %d exceeds maximum %d", opts.RecordSize, format.MaxRecordSize)
	}

	suite, err := NewCipherSuite(opts.CipherID)
	if err != nil {
		return err
	}
	wireCipherID, err := WireCipherID(opts.CipherID)
	if err != nil {
		return err
	}

	var salt [format.SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("crypto: generating salt: %w", err)
	}

	var kdfID format.KDFID
	var argon2Params kdf.Argon2Params
	switch opts.Credential.Kind {
	case kdf.SourcePassword:
		kdfID = format.KDFArgon2id
		argon2Params = opts.Argon2
		if err := argon2Params.Validate(); err != nil {
			return err
		}
	case kdf.SourceRaw:
		kdfID = format.KDFRaw
	default:
		return fmt.Errorf("crypto: unknown credential source kind %d", opts.Credential.Kind)
	}

	masterKey, err := kdf.DeriveMasterKey(opts.Credential, argon2Params, salt[:])
	if err != nil {
		return err
	}

	fileKey, err := kdf.DeriveFileKey(masterKey, salt[:], domainInfo(opts.CipherID), suite.KeySize())
	if err != nil {
		return err
	}

	header := &format.Header{
		Version:    format.Version1,
		CipherID:   wireCipherID,
		CodecID:    opts.CodecID,
		KDFID:      kdfID,
		Salt:       salt,
		RecordSize: opts.RecordSize,
	}
	if kdfID == format.KDFArgon2id {
		header.Argon2Time = argon2Params.Time
		header.Argon2MemoryKiB = argon2Params.MemoryKiB
		header.Argon2Parallelism = argon2Params.Parallelism
		header.Argon2KeyLength = argon2Params.KeyLength
	}

	headerBytes, err := header.Encode()
	if err != nil {
		return err
	}
	if n, err := w.Write(headerBytes); err != nil {
		return fmt.Errorf("crypto: writing header: %w", err)
	} else if n != len(headerBytes) {
		return fmt.Errorf("crypto: writing header: %w", io.ErrShortWrite)
	}

	aead, err := suite.NewAEAD(fileKey)
	if err != nil {
		return err
	}
	if aead.NonceSize() != suite.NonceSize() {
		return fmt.Errorf("crypto: internal error: aead nonce size %d does not match suite nonce size %d", aead.NonceSize(), suite.NonceSize())
	}

	buf := make([]byte, opts.RecordSize)
	var counter, totalPlaintext, totalCiphertext uint64

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			sealed, err := sealRecord(aead, opts.CipherID, headerBytes, format.RecordTypeData, counter, buf[:n])
			if err != nil {
				return err
			}
			if err := format.WriteRecord(w, format.RecordHeader{Type: format.RecordTypeData, Index: counter}, sealed); err != nil {
				return err
			}
			totalPlaintext += uint64(n)
			totalCiphertext += uint64(len(sealed))

			next, err := format.NextIndex(counter)
			if err != nil {
				return err
			}
			counter = next
		}

		if rerr == nil {
			continue
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		return fmt.Errorf("crypto: reading plaintext: %w", rerr)
	}

	final := format.FinalPayload{
		TotalDataRecords:     counter,
		TotalPlaintextBytes:  totalPlaintext,
		TotalCiphertextBytes: totalCiphertext,
	}
	sealedFinal, err := sealRecord(aead, opts.CipherID, headerBytes, format.RecordTypeFinal, counter, final.Marshal())
	if err != nil {
		return err
	}
	return format.WriteRecord(w, format.RecordHeader{Type: format.RecordTypeFinal, Index: counter}, sealedFinal)
}

// Decrypt reads a complete v1 protected-file container from r, verifies
// every record (header authenticity via AAD, per-record AEAD
// authentication, contiguous non-replayed non-reordered indices, and the
// authenticated final commit of total counts), and writes the recovered
// plaintext to w. It returns the codec ID stored in the header so the
// caller can run w's contents through the matching decompressor; restore
// never trusts header fields before the corresponding records authenticate.
//
// Decrypt fails closed on: unknown format version/cipher/codec, wrong
// credential kind for the file's KDF, authentication failure on any
// record, non-contiguous or replayed record indices, malformed record
// lengths, missing or duplicated final records, committed-count mismatches,
// and trailing bytes after the final record.
func Decrypt(ctx context.Context, r io.Reader, w io.Writer, cred kdf.Credential) (format.CodecID, error) {
	prefix := make([]byte, format.FixedPrefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return format.CodecUnknown, fmt.Errorf("crypto: reading header prefix: %w", err)
	}
	headerLen, err := format.PeekHeaderLength(prefix)
	if err != nil {
		return format.CodecUnknown, err
	}

	headerBytes := make([]byte, headerLen)
	copy(headerBytes, prefix)
	if _, err := io.ReadFull(r, headerBytes[format.FixedPrefixLen:]); err != nil {
		return format.CodecUnknown, fmt.Errorf("crypto: reading header: %w", err)
	}

	header, err := format.DecodeHeader(headerBytes)
	if err != nil {
		return format.CodecUnknown, err
	}

	cipherID, err := FromWireCipherID(header.CipherID)
	if err != nil {
		return format.CodecUnknown, err
	}
	suite, err := NewCipherSuite(cipherID)
	if err != nil {
		return format.CodecUnknown, err
	}

	var argon2Params kdf.Argon2Params
	switch header.KDFID {
	case format.KDFArgon2id:
		if cred.Kind != kdf.SourcePassword {
			return format.CodecUnknown, fmt.Errorf("crypto: this file was protected with a password and requires a password credential")
		}
		argon2Params = kdf.Argon2Params{
			Time:        header.Argon2Time,
			MemoryKiB:   header.Argon2MemoryKiB,
			Parallelism: header.Argon2Parallelism,
			KeyLength:   header.Argon2KeyLength,
		}
	case format.KDFRaw:
		if cred.Kind != kdf.SourceRaw {
			return format.CodecUnknown, fmt.Errorf("crypto: this file was protected with a raw key and requires a raw key credential")
		}
	default:
		return format.CodecUnknown, fmt.Errorf("crypto: unknown kdf id %d", header.KDFID)
	}

	masterKey, err := kdf.DeriveMasterKey(cred, argon2Params, header.Salt[:])
	if err != nil {
		return format.CodecUnknown, err
	}
	fileKey, err := kdf.DeriveFileKey(masterKey, header.Salt[:], domainInfo(cipherID), suite.KeySize())
	if err != nil {
		return format.CodecUnknown, err
	}
	aead, err := suite.NewAEAD(fileKey)
	if err != nil {
		return format.CodecUnknown, err
	}

	maxDataCipherLen := uint64(header.RecordSize) + uint64(aead.Overhead())
	expectFinalCipherLen := uint64(format.FinalPayloadLen) + uint64(aead.Overhead())

	var expectedIndex uint64
	var totalPlaintext, totalCiphertext uint64
	finalized := false

	for {
		if err := ctx.Err(); err != nil {
			return format.CodecUnknown, err
		}

		rh, rerr := format.ReadRecordHeader(r)
		if rerr == io.EOF {
			if !finalized {
				return format.CodecUnknown, fmt.Errorf("crypto: input ended before an authenticated final record")
			}
			break
		}
		if finalized {
			return format.CodecUnknown, fmt.Errorf("crypto: trailing data after final record")
		}
		if rerr != nil {
			return format.CodecUnknown, rerr
		}
		if rh.Index != expectedIndex {
			return format.CodecUnknown, fmt.Errorf("crypto: non-contiguous record index: expected %d, got %d", expectedIndex, rh.Index)
		}

		ciphertext, err := format.ReadRecordCiphertext(r, rh)
		if err != nil {
			return format.CodecUnknown, err
		}

		switch rh.Type {
		case format.RecordTypeData:
			if uint64(rh.CipherLen) > maxDataCipherLen {
				return format.CodecUnknown, fmt.Errorf("crypto: data record %d exceeds maximum size", rh.Index)
			}
			plaintext, err := openRecord(aead, cipherID, headerBytes, format.RecordTypeData, rh.Index, ciphertext)
			if err != nil {
				return format.CodecUnknown, fmt.Errorf("crypto: authentication failed for data record %d: %w", rh.Index, err)
			}
			if n, err := w.Write(plaintext); err != nil {
				return format.CodecUnknown, fmt.Errorf("crypto: writing plaintext: %w", err)
			} else if n != len(plaintext) {
				return format.CodecUnknown, fmt.Errorf("crypto: writing plaintext: %w", io.ErrShortWrite)
			}
			totalPlaintext += uint64(len(plaintext))
			totalCiphertext += uint64(len(ciphertext))

		case format.RecordTypeFinal:
			if uint64(rh.CipherLen) != expectFinalCipherLen {
				return format.CodecUnknown, fmt.Errorf("crypto: malformed final record length")
			}
			plaintext, err := openRecord(aead, cipherID, headerBytes, format.RecordTypeFinal, rh.Index, ciphertext)
			if err != nil {
				return format.CodecUnknown, fmt.Errorf("crypto: authentication failed for final record: %w", err)
			}
			payload, err := format.UnmarshalFinalPayload(plaintext)
			if err != nil {
				return format.CodecUnknown, err
			}
			if payload.TotalDataRecords != rh.Index {
				return format.CodecUnknown, fmt.Errorf("crypto: committed data record count mismatch")
			}
			if payload.TotalPlaintextBytes != totalPlaintext {
				return format.CodecUnknown, fmt.Errorf("crypto: committed plaintext byte count mismatch")
			}
			if payload.TotalCiphertextBytes != totalCiphertext {
				return format.CodecUnknown, fmt.Errorf("crypto: committed ciphertext byte count mismatch")
			}
			finalized = true
		}

		next, err := format.NextIndex(expectedIndex)
		if err != nil {
			return format.CodecUnknown, err
		}
		expectedIndex = next
	}

	return header.CodecID, nil
}

func domainInfo(id CipherID) string {
	return fmt.Sprintf("cypherstorm/v1/%s", id)
}
