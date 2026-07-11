package qrexchange

import (
	"path/filepath"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/identity"
)

func TestQRRoundTripAndChecksum(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "id.key")
	if err := identity.Generate("x25519", private); err != nil {
		t.Fatal(err)
	}
	public, err := identity.PublicFromPrivate(private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(public)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := identity.Fingerprint(public)
	b, _ := identity.Fingerprint(decoded)
	if a != b {
		t.Fatal("fingerprint changed")
	}
	png := filepath.Join(dir, "id.png")
	if err = PNG(public, png); err != nil {
		t.Fatal(err)
	}
	decoded, err = ImportPNG(png)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = identity.Fingerprint(decoded)
	if a != b {
		t.Fatal("PNG fingerprint changed")
	}
	last := encoded[len(encoded)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	tampered := encoded[:len(encoded)-1] + string(replacement)
	if _, err = Decode(tampered); err == nil {
		t.Fatal("tampered QR payload accepted")
	}
}
func FuzzDecode(f *testing.F) {
	f.Add("")
	f.Add("not-base64")
	f.Fuzz(func(t *testing.T, value string) { _, _ = Decode(value) })
}
