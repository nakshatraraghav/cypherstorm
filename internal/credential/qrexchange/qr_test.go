package qrexchange

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/identity"
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

func TestImportPNGRejectsOversizedImageBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.png")
	if err := os.WriteFile(path, pngHeader(uint32(maxImagePixels), 2), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	if _, err := ImportPNG(path); err == nil || !strings.Contains(err.Error(), "dimensions exceed") {
		t.Fatalf("ImportPNG oversized error = %v", err)
	}
}

func pngHeader(width, height uint32) []byte {
	data := make([]byte, 33)
	copy(data, "\x89PNG\r\n\x1a\n")
	binary.BigEndian.PutUint32(data[8:12], 13)
	copy(data[12:16], "IHDR")
	binary.BigEndian.PutUint32(data[16:20], width)
	binary.BigEndian.PutUint32(data[20:24], height)
	data[24] = 8
	data[25] = 2
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))
	return data
}
func FuzzDecode(f *testing.F) {
	f.Add("")
	f.Add("not-base64")
	f.Fuzz(func(t *testing.T, value string) { _, _ = Decode(value) })
}
