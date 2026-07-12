package container

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/identity"
	cyscrypto "github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
)

func TestRawRecipientVectorsAllSuites(t *testing.T) {
	plain := bytes.Repeat([]byte("v2-vector\x00"), 1000)
	raw := bytes.Repeat([]byte{0x42}, 32)
	for _, cipher := range cyscrypto.AllCipherIDs() {
		for _, codec := range compress.AllCodecs() {
			t.Run(string(cipher)+"/"+string(codec.ID()), func(t *testing.T) {
				var protected bytes.Buffer
				err := Encrypt(context.Background(), bytes.NewReader(plain), &protected, EncryptOptions{Cipher: cipher, Codec: codec.ID(), RecordSize: 257, Recipients: RecipientOptions{RawKey: raw}, Metadata: Metadata{OriginalName: "vector.bin", CredentialHint: "synthetic"}})
				if err != nil {
					t.Fatal(err)
				}
				var recovered bytes.Buffer
				gotCodec, metadata, err := Decrypt(context.Background(), bytes.NewReader(protected.Bytes()), &recovered, DecryptOptions{RawKey: raw})
				if err != nil {
					t.Fatal(err)
				}
				if gotCodec != codec.ID() || !bytes.Equal(recovered.Bytes(), plain) || metadata.CredentialHint != "synthetic" {
					t.Fatalf("round trip mismatch")
				}
				tampered := append([]byte(nil), protected.Bytes()...)
				tampered[len(tampered)-1] ^= 1
				if _, _, err = Decrypt(context.Background(), bytes.NewReader(tampered), new(bytes.Buffer), DecryptOptions{RawKey: raw}); err == nil {
					t.Fatal("tampered final record accepted")
				}
			})
		}
	}
}
func TestPasswordRecipientAndWrongCredential(t *testing.T) {
	var protected bytes.Buffer
	err := Encrypt(context.Background(), bytes.NewReader([]byte("secret")), &protected, EncryptOptions{Cipher: cyscrypto.AES256GCM, Codec: compress.CompressionGzip, Recipients: RecipientOptions{Password: []byte("correct")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = Decrypt(context.Background(), bytes.NewReader(protected.Bytes()), new(bytes.Buffer), DecryptOptions{Password: []byte("wrong")}); err == nil {
		t.Fatal("wrong password accepted")
	}
	var out bytes.Buffer
	if _, _, err = Decrypt(context.Background(), bytes.NewReader(protected.Bytes()), &out, DecryptOptions{Password: []byte("correct")}); err != nil || out.String() != "secret" {
		t.Fatalf("password round trip: %v", err)
	}
}
func TestX25519MixedRecipientsAndRekeyPayloadIdentity(t *testing.T) {
	dir := t.TempDir()
	alice := filepath.Join(dir, "alice.key")
	bob := filepath.Join(dir, "bob.key")
	if err := identity.Generate("x25519", alice); err != nil {
		t.Fatal(err)
	}
	if err := identity.Generate("x25519", bob); err != nil {
		t.Fatal(err)
	}
	alicePublic, _ := identity.PublicFromPrivate(alice)
	bobPublic, _ := identity.PublicFromPrivate(bob)
	raw := bytes.Repeat([]byte{7}, 32)
	var original bytes.Buffer
	if err := Encrypt(context.Background(), bytes.NewReader([]byte("payload")), &original, EncryptOptions{Cipher: cyscrypto.XChaCha20Poly1305, Codec: compress.CompressionZstd, Recipients: RecipientOptions{RawKey: raw, PublicKeys: []identity.Public{alicePublic}}}); err != nil {
		t.Fatal(err)
	}
	var rekeyed bytes.Buffer
	if _, err := Rekey(context.Background(), bytes.NewReader(original.Bytes()), &rekeyed, DecryptOptions{IdentityPaths: []string{alice}}, RecipientOptions{PublicKeys: []identity.Public{bobPublic}}, nil, false); err != nil {
		t.Fatal(err)
	}
	payload := func(data []byte) []byte { n := binary.BigEndian.Uint32(data[8:12]); return data[12+int(n):] }
	if !bytes.Equal(payload(original.Bytes()), payload(rekeyed.Bytes())) {
		t.Fatal("rekey changed payload ciphertext")
	}
	var out bytes.Buffer
	if _, _, err := Decrypt(context.Background(), bytes.NewReader(rekeyed.Bytes()), &out, DecryptOptions{IdentityPaths: []string{bob}}); err != nil || out.String() != "payload" {
		t.Fatalf("bob decrypt: %v", err)
	}
	if _, _, err := Decrypt(context.Background(), bytes.NewReader(rekeyed.Bytes()), new(bytes.Buffer), DecryptOptions{RawKey: raw}); err != nil {
		t.Fatalf("nonremoved raw recipient failed: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "unused"))
}

func TestReadHeaderRejectsMultiplePasswordRecipientsAndNonCanonicalJSON(t *testing.T) {
	header := Header{
		Version:    Version,
		PayloadID:  b64(make([]byte, 32)),
		Cipher:     string(cyscrypto.AES256GCM),
		Codec:      string(compress.CompressionGzip),
		RecordSize: 1,
		Recipients: []RecipientStanza{{Type: "password"}, {Type: "password"}},
	}
	data, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	container := make([]byte, 12+len(data))
	copy(container, Magic[:])
	binary.BigEndian.PutUint32(container[8:12], uint32(len(data)))
	copy(container[12:], data)
	if _, _, _, err := readHeader(bytes.NewReader(container)); err == nil || !strings.Contains(err.Error(), "multiple password") {
		t.Fatalf("multiple password recipients error = %v", err)
	}

	oneRecipient := header
	oneRecipient.Recipients = oneRecipient.Recipients[:1]
	data, err = json.Marshal(oneRecipient)
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte(" \n"), data...)
	container = make([]byte, 12+len(data))
	copy(container, Magic[:])
	binary.BigEndian.PutUint32(container[8:12], uint32(len(data)))
	copy(container[12:], data)
	if _, _, _, err := readHeader(bytes.NewReader(container)); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical header error = %v", err)
	}
}

func TestPasswordKDFHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Encrypt(ctx, bytes.NewReader([]byte("payload")), new(bytes.Buffer), EncryptOptions{
		Cipher: cyscrypto.AES256GCM, Codec: compress.CompressionGzip, Recipients: RecipientOptions{Password: []byte("password")},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt cancelled context error = %v", err)
	}
}
