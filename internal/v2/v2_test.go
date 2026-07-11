package v2

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	cyscrypto "github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/identity"
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
