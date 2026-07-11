// Package v2 implements the version-2 envelope-encrypted CypherStorm format.
package v2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	cyscrypto "github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/identity"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var Magic = [8]byte{'C', 'Y', 'S', 'V', '2', 0, 0, 0}

const Version = 2
const MaxHeaderSize = 1 << 20
const MaxRecipients = 64
const MaxMetadataSize = 1 << 20
const maxRecordSize = 16 << 20

type Metadata struct {
	OriginalName          string   `json:"original_name,omitempty"`
	SourceType            string   `json:"source_type,omitempty"`
	ProtectedAt           string   `json:"protected_at,omitempty"`
	Description           string   `json:"description,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	CredentialHint        string   `json:"credential_hint,omitempty"`
	CredentialFingerprint string   `json:"credential_fingerprint,omitempty"`
}
type Argon2Params struct {
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}
type RecipientStanza struct {
	Type    string        `json:"type"`
	ID      string        `json:"id,omitempty"`
	Salt    string        `json:"salt,omitempty"`
	Argon2  *Argon2Params `json:"argon2,omitempty"`
	Nonce   string        `json:"nonce,omitempty"`
	Wrapped string        `json:"wrapped"`
}
type Header struct {
	Version       int               `json:"version"`
	PayloadID     string            `json:"payload_id"`
	Cipher        string            `json:"cipher"`
	Codec         string            `json:"codec"`
	RecordSize    uint32            `json:"record_size"`
	NoncePrefix   string            `json:"nonce_prefix"`
	MetadataNonce string            `json:"metadata_nonce"`
	Metadata      string            `json:"metadata"`
	Recipients    []RecipientStanza `json:"recipients"`
	PublicHint    string            `json:"public_hint,omitempty"`
}
type InspectResult struct {
	Header        Header
	HeaderLength  uint32
	PayloadOffset int64
}
type RecipientOptions struct {
	Password   []byte
	RawKey     []byte
	PublicKeys []identity.Public
}
type DecryptOptions struct {
	Password      []byte
	RawKey        []byte
	IdentityPaths []string
}
type EncryptOptions struct {
	Cipher     cyscrypto.CipherID
	Codec      compress.CompressionID
	RecordSize uint32
	Recipients RecipientOptions
	Metadata   Metadata
	PublicHint string
}
type immutableHeader struct {
	Version     int    `json:"version"`
	PayloadID   string `json:"payload_id"`
	Cipher      string `json:"cipher"`
	Codec       string `json:"codec"`
	RecordSize  uint32 `json:"record_size"`
	NoncePrefix string `json:"nonce_prefix"`
}

func Encrypt(ctx context.Context, r io.Reader, w io.Writer, o EncryptOptions) error {
	if o.RecordSize == 0 {
		o.RecordSize = 64 << 10
	}
	if o.RecordSize > maxRecordSize {
		return fmt.Errorf("v2: record size exceeds limit")
	}
	suite, err := cyscrypto.NewCipherSuite(o.Cipher)
	if err != nil {
		return err
	}
	if _, err = compress.NewCodec(o.Codec); err != nil {
		return err
	}
	contentKey := make([]byte, 32)
	if _, err = rand.Read(contentKey); err != nil {
		return err
	}
	defer clear(contentKey)
	payloadID, err := random(32)
	if err != nil {
		return err
	}
	noncePrefix, err := random(suite.NonceSize() - 8)
	if err != nil {
		return err
	}
	immutable := immutableHeader{Version: Version, PayloadID: b64(payloadID), Cipher: string(o.Cipher), Codec: string(o.Codec), RecordSize: o.RecordSize, NoncePrefix: b64(noncePrefix)}
	aad, _ := json.Marshal(immutable)
	payloadKey, err := derive(contentKey, payloadID, "cypherstorm/v2/payload", suite.KeySize())
	if err != nil {
		return err
	}
	defer clear(payloadKey)
	metadataKey, err := derive(contentKey, payloadID, "cypherstorm/v2/metadata", 32)
	if err != nil {
		return err
	}
	defer clear(metadataKey)
	stanzas, err := wrapRecipients(contentKey, payloadID, o.Recipients)
	if err != nil {
		return err
	}
	metaData, err := json.Marshal(o.Metadata)
	if err != nil || len(metaData) > MaxMetadataSize {
		return fmt.Errorf("v2: metadata exceeds limit")
	}
	metaAEAD, _ := chacha20poly1305.NewX(metadataKey)
	metaNonce, err := random(metaAEAD.NonceSize())
	if err != nil {
		return err
	}
	encryptedMeta := metaAEAD.Seal(nil, metaNonce, metaData, aad)
	header := Header{Version: Version, PayloadID: immutable.PayloadID, Cipher: immutable.Cipher, Codec: immutable.Codec, RecordSize: o.RecordSize, NoncePrefix: immutable.NoncePrefix, MetadataNonce: b64(metaNonce), Metadata: b64(encryptedMeta), Recipients: stanzas, PublicHint: o.PublicHint}
	if len(header.PublicHint) > 256 {
		return fmt.Errorf("v2: public hint exceeds limit")
	}
	headerBytes, err := json.Marshal(header)
	if err != nil || len(headerBytes) > MaxHeaderSize {
		return fmt.Errorf("v2: header exceeds limit")
	}
	if _, err = w.Write(Magic[:]); err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(headerBytes)))
	if _, err = w.Write(length[:]); err != nil {
		return err
	}
	if _, err = w.Write(headerBytes); err != nil {
		return err
	}
	aead, err := suite.NewAEAD(payloadKey)
	if err != nil {
		return err
	}
	buf := make([]byte, o.RecordSize)
	var index, totalPlain, totalCipher uint64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, re := io.ReadFull(r, buf)
		if n > 0 {
			nonce := recordNonce(noncePrefix, index, aead.NonceSize())
			recordAAD := recordAAD(aad, 1, index)
			sealed := aead.Seal(nil, nonce, buf[:n], recordAAD)
			if err = writeRecord(w, 1, index, sealed); err != nil {
				return err
			}
			index++
			totalPlain += uint64(n)
			totalCipher += uint64(len(sealed))
		}
		if re == nil {
			continue
		}
		if re == io.EOF || re == io.ErrUnexpectedEOF {
			break
		}
		return re
	}
	final := make([]byte, 24)
	binary.BigEndian.PutUint64(final, index)
	binary.BigEndian.PutUint64(final[8:], totalPlain)
	binary.BigEndian.PutUint64(final[16:], totalCipher)
	sealed := aead.Seal(nil, recordNonce(noncePrefix, index, aead.NonceSize()), final, recordAAD(aad, 2, index))
	return writeRecord(w, 2, index, sealed)
}

func Decrypt(ctx context.Context, r io.Reader, w io.Writer, o DecryptOptions) (compress.CompressionID, Metadata, error) {
	header, _, aad, err := readHeader(r)
	if err != nil {
		return "", Metadata{}, err
	}
	payloadID, _ := base64.RawStdEncoding.DecodeString(header.PayloadID)
	contentKey, err := unwrapRecipients(header.Recipients, payloadID, o)
	if err != nil {
		return "", Metadata{}, err
	}
	defer clear(contentKey)
	cipherID := cyscrypto.CipherID(header.Cipher)
	suite, err := cyscrypto.NewCipherSuite(cipherID)
	if err != nil {
		return "", Metadata{}, err
	}
	payloadKey, err := derive(contentKey, payloadID, "cypherstorm/v2/payload", suite.KeySize())
	if err != nil {
		return "", Metadata{}, err
	}
	defer clear(payloadKey)
	aead, err := suite.NewAEAD(payloadKey)
	if err != nil {
		return "", Metadata{}, err
	}
	prefix, err := decodeFixed(header.NoncePrefix, aead.NonceSize()-8)
	if err != nil {
		return "", Metadata{}, err
	}
	var expected, totalPlain, totalCipher uint64
	finalized := false
	for {
		if err = ctx.Err(); err != nil {
			return "", Metadata{}, err
		}
		typ, index, ciphertext, re := readRecord(r, uint32(header.RecordSize)+uint32(aead.Overhead()))
		if re == io.EOF {
			if !finalized {
				return "", Metadata{}, fmt.Errorf("v2: missing final record")
			}
			break
		}
		if re != nil {
			return "", Metadata{}, re
		}
		if finalized {
			return "", Metadata{}, fmt.Errorf("v2: trailing bytes")
		}
		if index != expected {
			return "", Metadata{}, fmt.Errorf("v2: non-contiguous record index")
		}
		plain, e := aead.Open(nil, recordNonce(prefix, index, aead.NonceSize()), ciphertext, recordAAD(aad, typ, index))
		if e != nil {
			return "", Metadata{}, fmt.Errorf("v2: payload authentication failed: %w", e)
		}
		switch typ {
		case 1:
			if len(plain) > int(header.RecordSize) {
				return "", Metadata{}, fmt.Errorf("v2: record too large")
			}
			if _, e = w.Write(plain); e != nil {
				return "", Metadata{}, e
			}
			totalPlain += uint64(len(plain))
			totalCipher += uint64(len(ciphertext))
		case 2:
			if len(plain) != 24 {
				return "", Metadata{}, fmt.Errorf("v2: malformed final record")
			}
			if binary.BigEndian.Uint64(plain) != index || binary.BigEndian.Uint64(plain[8:]) != totalPlain || binary.BigEndian.Uint64(plain[16:]) != totalCipher {
				return "", Metadata{}, fmt.Errorf("v2: final commitment mismatch")
			}
			finalized = true
		default:
			return "", Metadata{}, fmt.Errorf("v2: unknown record type")
		}
		expected++
	}
	metadataKey, _ := derive(contentKey, payloadID, "cypherstorm/v2/metadata", 32)
	defer clear(metadataKey)
	metaAEAD, _ := chacha20poly1305.NewX(metadataKey)
	nonce, err := decodeFixed(header.MetadataNonce, metaAEAD.NonceSize())
	if err != nil {
		return "", Metadata{}, err
	}
	encrypted, err := base64.RawStdEncoding.DecodeString(header.Metadata)
	if err != nil || len(encrypted) > MaxMetadataSize+metaAEAD.Overhead() {
		return "", Metadata{}, fmt.Errorf("v2: malformed metadata")
	}
	plainMeta, err := metaAEAD.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return "", Metadata{}, fmt.Errorf("v2: metadata authentication failed")
	}
	var metadata Metadata
	if err = json.Unmarshal(plainMeta, &metadata); err != nil {
		return "", Metadata{}, err
	}
	return compress.CompressionID(header.Codec), metadata, nil
}

func Inspect(r io.Reader) (InspectResult, error) {
	h, n, _, err := readHeader(r)
	return InspectResult{Header: h, HeaderLength: uint32(n), PayloadOffset: int64(12 + n)}, err
}
func Rekey(ctx context.Context, r io.Reader, w io.Writer, auth DecryptOptions, additions RecipientOptions, removeIDs []string, replaceSymmetric bool) (int64, error) {
	header, _, _, err := readHeader(r)
	if err != nil {
		return 0, err
	}
	payloadID, _ := base64.RawStdEncoding.DecodeString(header.PayloadID)
	contentKey, err := unwrapRecipients(header.Recipients, payloadID, auth)
	if err != nil {
		return 0, err
	}
	defer clear(contentKey)
	remove := make(map[string]bool, len(removeIDs))
	for _, id := range removeIDs {
		remove[id] = true
	}
	kept := make([]RecipientStanza, 0, len(header.Recipients))
	for _, stanza := range header.Recipients {
		if remove[stanza.ID] {
			continue
		}
		if replaceSymmetric && (stanza.Type == "password" || stanza.Type == "raw-key") {
			continue
		}
		kept = append(kept, stanza)
	}
	if len(additions.Password) > 0 || len(additions.RawKey) > 0 || len(additions.PublicKeys) > 0 {
		added, wrapErr := wrapRecipients(contentKey, payloadID, additions)
		if wrapErr != nil {
			return 0, wrapErr
		}
		kept = append(kept, added...)
	}
	if len(kept) == 0 || len(kept) > MaxRecipients {
		return 0, fmt.Errorf("v2: replacement envelope must contain 1..%d recipients", MaxRecipients)
	}
	seen := map[string]bool{}
	for _, stanza := range kept {
		if stanza.ID != "" && seen[stanza.ID] {
			return 0, fmt.Errorf("v2: duplicate recipient %s", stanza.ID)
		}
		seen[stanza.ID] = stanza.ID != ""
	}
	header.Recipients = kept
	encoded, _ := json.Marshal(header)
	if len(encoded) > MaxHeaderSize {
		return 0, fmt.Errorf("v2: replacement envelope too large")
	}
	if _, err = w.Write(Magic[:]); err != nil {
		return 0, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err = w.Write(length[:]); err != nil {
		return 0, err
	}
	if _, err = w.Write(encoded); err != nil {
		return 0, err
	}
	return io.Copy(w, contextReader{ctx, r})
}

func readHeader(r io.Reader) (Header, int, []byte, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return Header{}, 0, nil, err
	}
	if magic != Magic {
		return Header{}, 0, nil, fmt.Errorf("v2: bad magic")
	}
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return Header{}, 0, nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > MaxHeaderSize {
		return Header{}, 0, nil, fmt.Errorf("v2: invalid header length")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return Header{}, 0, nil, err
	}
	var h Header
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return Header{}, 0, nil, err
	}
	if h.Version != Version || h.RecordSize == 0 || h.RecordSize > maxRecordSize || len(h.Recipients) == 0 || len(h.Recipients) > MaxRecipients {
		return Header{}, 0, nil, fmt.Errorf("v2: invalid header")
	}
	if _, err := compress.NewCodec(compress.CompressionID(h.Codec)); err != nil {
		return Header{}, 0, nil, err
	}
	if _, err := cyscrypto.NewCipherSuite(cyscrypto.CipherID(h.Cipher)); err != nil {
		return Header{}, 0, nil, err
	}
	if _, err := decodeFixed(h.PayloadID, 32); err != nil {
		return Header{}, 0, nil, err
	}
	immutable := immutableHeader{Version: h.Version, PayloadID: h.PayloadID, Cipher: h.Cipher, Codec: h.Codec, RecordSize: h.RecordSize, NoncePrefix: h.NoncePrefix}
	aad, _ := json.Marshal(immutable)
	return h, int(n), aad, nil
}
func wrapRecipients(contentKey, payloadID []byte, o RecipientOptions) ([]RecipientStanza, error) {
	var out []RecipientStanza
	if len(o.Password) > 0 {
		salt, err := random(32)
		if err != nil {
			return nil, err
		}
		params := kdf.DefaultArgon2Params()
		key := kdf.Argon2Params{Time: params.Time, MemoryKiB: params.MemoryKiB, Parallelism: params.Parallelism, KeyLength: 32}
		kek, err := kdf.DeriveMasterKey(kdf.Credential{Kind: kdf.SourcePassword, Password: o.Password}, key, salt)
		if err != nil {
			return nil, err
		}
		nonce, err := random(chacha20poly1305.NonceSizeX)
		if err != nil {
			clear(kek)
			return nil, err
		}
		a, _ := chacha20poly1305.NewX(kek)
		wrapped := a.Seal(nil, nonce, contentKey, append(payloadID, []byte("password")...))
		clear(kek)
		out = append(out, RecipientStanza{Type: "password", Salt: b64(salt), Argon2: &Argon2Params{key.Time, key.MemoryKiB, key.Parallelism}, Nonce: b64(nonce), Wrapped: b64(wrapped)})
	}
	if len(o.RawKey) > 0 {
		if len(o.RawKey) != 32 {
			return nil, fmt.Errorf("v2: raw key must be 32 bytes")
		}
		salt, err := random(32)
		if err != nil {
			return nil, err
		}
		kek, err := derive(o.RawKey, salt, "cypherstorm/v2/raw-wrap", 32)
		if err != nil {
			return nil, err
		}
		nonce, err := random(chacha20poly1305.NonceSizeX)
		if err != nil {
			clear(kek)
			return nil, err
		}
		a, _ := chacha20poly1305.NewX(kek)
		wrapped := a.Seal(nil, nonce, contentKey, append(payloadID, []byte("raw-key")...))
		clear(kek)
		out = append(out, RecipientStanza{Type: "raw-key", Salt: b64(salt), Nonce: b64(nonce), Wrapped: b64(wrapped)})
	}
	seen := map[string]bool{}
	for _, p := range o.PublicKeys {
		recipient, err := identity.ParseX25519Recipient(p)
		if err != nil {
			return nil, err
		}
		id, err := identity.Fingerprint(p)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, fmt.Errorf("v2: duplicate recipient %s", id)
		}
		seen[id] = true
		var buf bytes.Buffer
		aw, err := age.Encrypt(&buf, recipient)
		if err != nil {
			return nil, err
		}
		_, _ = aw.Write(append(append([]byte(nil), payloadID...), contentKey...))
		if err = aw.Close(); err != nil {
			return nil, err
		}
		out = append(out, RecipientStanza{Type: "x25519", ID: id, Wrapped: b64(buf.Bytes())})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("v2: at least one recipient is required")
	}
	if len(out) > MaxRecipients {
		return nil, fmt.Errorf("v2: recipient limit exceeded")
	}
	return out, nil
}
func unwrapRecipients(stanzas []RecipientStanza, payloadID []byte, o DecryptOptions) ([]byte, error) {
	for _, s := range stanzas {
		var key []byte
		switch s.Type {
		case "password":
			if len(o.Password) == 0 || s.Argon2 == nil {
				continue
			}
			salt, e := decodeFixed(s.Salt, 32)
			if e != nil {
				return nil, e
			}
			params := kdf.Argon2Params{Time: s.Argon2.Time, MemoryKiB: s.Argon2.MemoryKiB, Parallelism: s.Argon2.Parallelism, KeyLength: 32}
			key, e = kdf.DeriveMasterKey(kdf.Credential{Kind: kdf.SourcePassword, Password: o.Password}, params, salt)
			if e != nil {
				return nil, e
			}
		case "raw-key":
			if len(o.RawKey) == 0 {
				continue
			}
			salt, e := decodeFixed(s.Salt, 32)
			if e != nil {
				return nil, e
			}
			key, e = derive(o.RawKey, salt, "cypherstorm/v2/raw-wrap", 32)
			if e != nil {
				return nil, e
			}
		case "x25519":
			for _, path := range o.IdentityPaths {
				id, e := identity.ParseX25519Private(path)
				if e != nil {
					continue
				}
				wrapped, e := base64.RawStdEncoding.DecodeString(s.Wrapped)
				if e != nil {
					return nil, e
				}
				reader, e := age.Decrypt(bytes.NewReader(wrapped), id)
				if e != nil {
					continue
				}
				plain, e := io.ReadAll(io.LimitReader(reader, 65))
				if e == nil && len(plain) == 64 && bytes.Equal(plain[:32], payloadID) {
					return append([]byte(nil), plain[32:]...), nil
				}
			}
			continue
		default:
			return nil, fmt.Errorf("v2: unknown recipient type %q", s.Type)
		}
		nonce, e := decodeFixed(s.Nonce, chacha20poly1305.NonceSizeX)
		if e != nil {
			return nil, e
		}
		wrapped, e := base64.RawStdEncoding.DecodeString(s.Wrapped)
		if e != nil {
			return nil, e
		}
		a, e := chacha20poly1305.NewX(key)
		clear(key)
		if e != nil {
			return nil, e
		}
		label := s.Type
		if label == "raw-key" {
			label = "raw-key"
		}
		plain, e := a.Open(nil, nonce, wrapped, append(payloadID, []byte(label)...))
		if e == nil && len(plain) == 32 {
			return plain, nil
		}
	}
	return nil, fmt.Errorf("v2: no recipient accepted the supplied credential")
}
func derive(secret, salt []byte, info string, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, n)
	_, err := io.ReadFull(r, out)
	return out, err
}
func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("v2: generate random bytes: %w", err)
	}
	return b, nil
}
func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func decodeFixed(s string, n int) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("v2: malformed fixed field")
	}
	return b, nil
}
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func recordNonce(prefix []byte, index uint64, size int) []byte {
	n := make([]byte, size)
	copy(n, prefix)
	binary.BigEndian.PutUint64(n[size-8:], index)
	return n
}
func recordAAD(header []byte, typ byte, index uint64) []byte {
	out := make([]byte, len(header)+9)
	copy(out, header)
	out[len(header)] = typ
	binary.BigEndian.PutUint64(out[len(header)+1:], index)
	return out
}
func writeRecord(w io.Writer, typ byte, index uint64, ciphertext []byte) error {
	var h [13]byte
	h[0] = typ
	binary.BigEndian.PutUint64(h[1:], index)
	binary.BigEndian.PutUint32(h[9:], uint32(len(ciphertext)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}
func readRecord(r io.Reader, max uint32) (byte, uint64, []byte, error) {
	var h [13]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[9:])
	if n > max+64 {
		return 0, 0, nil, fmt.Errorf("v2: record length exceeds limit")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return h[0], binary.BigEndian.Uint64(h[1:]), b, err
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

var _ = errors.Is
