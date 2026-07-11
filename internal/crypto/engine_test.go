package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/format"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

func passwordCred(pw string) kdf.Credential {
	return kdf.Credential{Kind: kdf.SourcePassword, Password: []byte(pw)}
}

func rawCred(key []byte) kdf.Credential {
	return kdf.Credential{Kind: kdf.SourceRaw, RawKey: key}
}

func cheapArgon2Params() kdf.Argon2Params {
	return kdf.Argon2Params{
		Time:        1,
		MemoryKiB:   8,
		Parallelism: 1,
		KeyLength:   kdf.MasterKeySize,
	}
}

func encryptAll(t *testing.T, plaintext []byte, cred kdf.Credential, cipherID CipherID, recordSize uint32) []byte {
	t.Helper()
	var out bytes.Buffer
	opts := EncryptOptions{
		Credential: cred,
		CipherID:   cipherID,
		CodecID:    format.CodecGzip,
		Argon2:     cheapArgon2Params(),
		RecordSize: recordSize,
	}
	if err := Encrypt(context.Background(), bytes.NewReader(plaintext), &out, opts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return out.Bytes()
}

func TestRoundTrip_PasswordAndRawKey_BothCiphers_BoundarySizes(t *testing.T) {
	const recordSize = 16
	sizes := []int{0, 1, recordSize - 1, recordSize, recordSize + 1, recordSize*3 + 5, 5000}

	for _, cipherID := range AllCipherIDs() {
		for _, size := range sizes {
			plaintext := testutil.RandomBytes(t, size)

			t.Run(string(cipherID), func(t *testing.T) {
				// Password credential.
				container := encryptAll(t, plaintext, passwordCred("correct horse battery staple"), cipherID, recordSize)
				var restored bytes.Buffer
				codecID, err := Decrypt(context.Background(), bytes.NewReader(container), &restored, passwordCred("correct horse battery staple"))
				if err != nil {
					t.Fatalf("password Decrypt size=%d: %v", size, err)
				}
				if codecID != format.CodecGzip {
					t.Fatalf("codec id mismatch: got %v", codecID)
				}
				if !bytes.Equal(restored.Bytes(), plaintext) {
					t.Fatalf("password round trip mismatch at size=%d", size)
				}

				// Raw key credential.
				rawKey := testutil.RawKey(t, kdf.MasterKeySize)
				container2 := encryptAll(t, plaintext, rawCred(rawKey), cipherID, recordSize)
				var restored2 bytes.Buffer
				if _, err := Decrypt(context.Background(), bytes.NewReader(container2), &restored2, rawCred(rawKey)); err != nil {
					t.Fatalf("raw key Decrypt size=%d: %v", size, err)
				}
				if !bytes.Equal(restored2.Bytes(), plaintext) {
					t.Fatalf("raw key round trip mismatch at size=%d", size)
				}
			})
		}
	}
}

func TestRoundTrip_ProductionDefaultArgon2(t *testing.T) {
	plaintext := []byte("production-default Argon2 smoke test")
	var container bytes.Buffer
	opts := EncryptOptions{
		Credential: passwordCred("correct horse battery staple"),
		CipherID:   AES256GCM,
		CodecID:    format.CodecGzip,
		Argon2:     kdf.DefaultArgon2Params(),
		RecordSize: 64,
	}
	if err := Encrypt(context.Background(), bytes.NewReader(plaintext), &container, opts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var restored bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(container.Bytes()), &restored, opts.Credential); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), plaintext) {
		t.Fatal("production-default Argon2 round trip mismatch")
	}
}

func TestDecrypt_WrongPassword_Fails(t *testing.T) {
	container := encryptAll(t, []byte("secret data"), passwordCred("right password"), AES256GCM, 64)
	var out bytes.Buffer
	_, err := Decrypt(context.Background(), bytes.NewReader(container), &out, passwordCred("wrong password"))
	if err == nil {
		t.Fatal("expected error decrypting with wrong password, got nil")
	}
}

func TestDecrypt_WrongRawKey_Fails(t *testing.T) {
	key1 := testutil.RawKey(t, kdf.MasterKeySize)
	key2 := testutil.RawKey(t, kdf.MasterKeySize)
	container := encryptAll(t, []byte("secret data"), rawCred(key1), XChaCha20Poly1305, 64)
	var out bytes.Buffer
	_, err := Decrypt(context.Background(), bytes.NewReader(container), &out, rawCred(key2))
	if err == nil {
		t.Fatal("expected error decrypting with wrong raw key, got nil")
	}
}

func TestDecrypt_CredentialKindMismatch_Fails(t *testing.T) {
	container := encryptAll(t, []byte("data"), passwordCred("pw"), AES256GCM, 64)
	var out bytes.Buffer
	key := testutil.RawKey(t, kdf.MasterKeySize)
	if _, err := Decrypt(context.Background(), bytes.NewReader(container), &out, rawCred(key)); err == nil {
		t.Fatal("expected error using raw key credential against password-protected file")
	}
}

func TestDecrypt_TamperedHeader_Fails(t *testing.T) {
	container := encryptAll(t, []byte("data payload"), passwordCred("pw"), AES256GCM, 64)
	tampered := append([]byte(nil), container...)
	tampered[24] ^= 0xFF // first byte of the salt
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting with tampered header")
	}
}

func TestDecrypt_OutOfPolicyArgon2Header_FailsBeforeDerivation(t *testing.T) {
	container := encryptAll(t, []byte("data payload"), passwordCred("pw"), AES256GCM, 64)
	tampered := append([]byte(nil), container...)
	binary.BigEndian.PutUint32(tampered[18:22], kdf.MaxArgon2MemoryKiB+1)

	var out bytes.Buffer
	_, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, passwordCred("pw"))
	if err == nil {
		t.Fatal("expected out-of-policy Argon2 header to fail")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected resource-policy error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("decrypt wrote %d bytes before rejecting hostile KDF parameters", out.Len())
	}
}

func TestDecrypt_TamperedDataRecord_Fails(t *testing.T) {
	container := encryptAll(t, []byte("0123456789abcdef0123456789abcdef"), passwordCred("pw"), AES256GCM, 16)
	tampered := append([]byte(nil), container...)
	// Flip a byte well past the header, inside the first record's ciphertext.
	tampered[format.HeaderLenV1+format.RecordHeaderLen+2] ^= 0xFF
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting with tampered data record")
	}
}

func TestDecrypt_TruncatedBeforeFinalRecord_Fails(t *testing.T) {
	container := encryptAll(t, testutil.RandomBytes(t, 100), passwordCred("pw"), AES256GCM, 16)
	// Chop off the trailing bytes so the final record never arrives:
	// this must be rejected as "valid-prefix truncation", not silently
	// accepted as a short-but-legitimate file.
	truncated := container[:len(container)-5]
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(truncated), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting truncated container missing final record")
	}
}

func TestDecrypt_TrailingGarbageAfterFinalRecord_Fails(t *testing.T) {
	container := encryptAll(t, []byte("hello"), passwordCred("pw"), AES256GCM, 16)
	withGarbage := append(append([]byte(nil), container...), 0xDE, 0xAD, 0xBE, 0xEF)
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(withGarbage), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting container with trailing garbage")
	}
}

func TestDecrypt_TamperedFinalRecordFails(t *testing.T) {
	key := testutil.RawKey(t, kdf.MasterKeySize)
	container := encryptAll(t, []byte("final record"), rawCred(key), XChaCha20Poly1305, 8)
	tampered := append([]byte(nil), container...)
	tampered[len(tampered)-1] ^= 0xff
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, rawCred(key)); err == nil {
		t.Fatal("expected tampered final record to fail")
	}
}

func TestDecrypt_ReorderedAndDuplicatedRecordsFail(t *testing.T) {
	key := testutil.RawKey(t, kdf.MasterKeySize)
	container := encryptAll(t, bytes.Repeat([]byte("record"), 20), rawCred(key), AES256GCM, 16)
	records := splitContainerRecords(t, container)
	if len(records) < 3 {
		t.Fatalf("need at least two data records and a final record, got %d", len(records))
	}

	reordered := append([]byte(nil), container[:format.HeaderLenV1]...)
	reordered = append(reordered, records[1]...)
	reordered = append(reordered, records[0]...)
	for _, record := range records[2:] {
		reordered = append(reordered, record...)
	}
	var reorderedOut bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(reordered), &reorderedOut, rawCred(key)); err == nil {
		t.Fatal("expected reordered records to fail")
	}

	duplicated := append([]byte(nil), container[:format.HeaderLenV1]...)
	duplicated = append(duplicated, records[0]...)
	duplicated = append(duplicated, records[0]...)
	for _, record := range records[1:] {
		duplicated = append(duplicated, record...)
	}
	var duplicatedOut bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(duplicated), &duplicatedOut, rawCred(key)); err == nil {
		t.Fatal("expected duplicated records to fail")
	}
}

func splitContainerRecords(t *testing.T, container []byte) [][]byte {
	t.Helper()
	body := container[format.HeaderLenV1:]
	var records [][]byte
	for len(body) > 0 {
		header, err := format.ReadRecordHeader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("ReadRecordHeader: %v", err)
		}
		length := format.RecordHeaderLen + int(header.CipherLen)
		if length > len(body) {
			t.Fatalf("record length %d exceeds remaining body %d", length, len(body))
		}
		records = append(records, append([]byte(nil), body[:length]...))
		body = body[length:]
	}
	return records
}

func TestDecrypt_UnknownVersion_Fails(t *testing.T) {
	container := encryptAll(t, []byte("hello"), passwordCred("pw"), AES256GCM, 16)
	tampered := append([]byte(nil), container...)
	tampered[8] = 99 // version byte
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting unknown format version")
	}
}

func TestDecrypt_UnknownCipherID_Fails(t *testing.T) {
	container := encryptAll(t, []byte("hello"), passwordCred("pw"), AES256GCM, 16)
	tampered := append([]byte(nil), container...)
	tampered[11] = 99 // cipher id byte
	var out bytes.Buffer
	if _, err := Decrypt(context.Background(), bytes.NewReader(tampered), &out, passwordCred("pw")); err == nil {
		t.Fatal("expected error decrypting unknown cipher id")
	}
}

func TestEncryptRejectsOversizedRecordBeforeAllocation(t *testing.T) {
	var output bytes.Buffer
	err := Encrypt(context.Background(), bytes.NewReader(nil), &output, EncryptOptions{
		Credential: rawCred(testutil.RawKey(t, kdf.MasterKeySize)),
		CipherID:   AES256GCM,
		CodecID:    format.CodecGzip,
		RecordSize: format.MaxRecordSize + 1,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected record-size policy error, got %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("Encrypt wrote %d bytes before rejecting record size", output.Len())
	}
}

func TestNewCipherSuite_UnsupportedID_Fails(t *testing.T) {
	if _, err := NewCipherSuite("twofish"); err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

func TestEachRecordUsesUniqueNonce(t *testing.T) {
	// Encrypt enough data to span multiple records and confirm no two
	// data records produce identical ciphertext bytes even though the
	// plaintext chunks are identical (proves nonces differ per record).
	const recordSize = 8
	plaintext := bytes.Repeat([]byte("AAAAAAAA"), 5) // 5 identical 8-byte chunks
	container := encryptAll(t, plaintext, rawCred(testutil.RawKey(t, kdf.MasterKeySize)), AES256GCM, recordSize)

	body := container[format.HeaderLenV1:]
	seen := map[string]bool{}
	for len(body) > 0 {
		rh, err := format.ReadRecordHeader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("ReadRecordHeader: %v", err)
		}
		total := format.RecordHeaderLen + int(rh.CipherLen)
		record := body[:total]
		ciphertext := string(record[format.RecordHeaderLen:])
		if seen[ciphertext] {
			t.Fatalf("duplicate ciphertext observed across records: nonce reuse")
		}
		seen[ciphertext] = true
		body = body[total:]
	}
	if len(seen) < 5 {
		t.Fatalf("expected at least 5 records, saw %d", len(seen))
	}
}
