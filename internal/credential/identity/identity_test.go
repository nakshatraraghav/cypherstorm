package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetachedSignatureMutation(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "sign.key")
	input := filepath.Join(dir, "archive.cys")
	sig := input + ".sig"
	if err := Generate("signing", key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("protected bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Sign(input, key, sig, "release"); err != nil {
		t.Fatal(err)
	}
	public, err := PublicFromPrivate(key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := Fingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(input, sig, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("protected byteS"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(input, sig, fingerprint); err == nil {
		t.Fatal("mutated archive accepted")
	}
}

func TestDetachedSignatureRejectsUntrustedSigner(t *testing.T) {
	dir := t.TempDir()
	signer := filepath.Join(dir, "signer.key")
	untrusted := filepath.Join(dir, "untrusted.key")
	input := filepath.Join(dir, "archive.cys")
	sig := input + ".sig"
	for _, path := range []string{signer, untrusted} {
		if err := Generate("signing", path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(input, []byte("protected bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Sign(input, signer, sig, "release"); err != nil {
		t.Fatal(err)
	}
	untrustedPublic, err := PublicFromPrivate(untrusted)
	if err != nil {
		t.Fatal(err)
	}
	untrustedFingerprint, err := Fingerprint(untrustedPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(input, sig, untrustedFingerprint); err == nil {
		t.Fatal("signature from an untrusted signer was accepted")
	}
}
func TestFingerprintDomainsDiffer(t *testing.T) {
	sign := Public{Version: 1, Type: "signing", Key: "same"}
	x := Public{Version: 1, Type: "x25519", Key: "same"}
	a, _ := Fingerprint(sign)
	b, _ := Fingerprint(x)
	if a == b {
		t.Fatal("fingerprint domains collide")
	}
}
