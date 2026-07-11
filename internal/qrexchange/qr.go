package qrexchange

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/identity"
	qrencode "github.com/skip2/go-qrcode"
)

type Payload struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
	Label     string `json:"label,omitempty"`
	Checksum  string `json:"checksum"`
}

func Encode(public identity.Public) (string, error) {
	if public.Type != "x25519" || len(public.Label) > 256 {
		return "", fmt.Errorf("qr: only bounded X25519 public identities are supported")
	}
	p := Payload{Version: 1, Type: public.Type, PublicKey: public.Key, Label: public.Label}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", p.Version, p.Type, p.PublicKey, p.Label)))
	p.Checksum = hex.EncodeToString(sum[:8])
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("qr: payload exceeds limit")
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func Decode(value string) (identity.Public, error) {
	if len(value) > 8192 {
		return identity.Public{}, fmt.Errorf("qr: encoded payload exceeds limit")
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return identity.Public{}, err
	}
	var p Payload
	if err = json.Unmarshal(data, &p); err != nil {
		return identity.Public{}, err
	}
	if p.Version != 1 || p.Type != "x25519" || len(p.PublicKey) > 4096 || len(p.Label) > 256 {
		return identity.Public{}, fmt.Errorf("qr: invalid payload")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", p.Version, p.Type, p.PublicKey, p.Label)))
	if p.Checksum != hex.EncodeToString(sum[:8]) {
		return identity.Public{}, fmt.Errorf("qr: checksum mismatch")
	}
	return identity.Public{Version: 1, Type: p.Type, Key: p.PublicKey, Label: p.Label}, nil
}
func Terminal(public identity.Public) (string, error) {
	value, err := Encode(public)
	if err != nil {
		return "", err
	}
	code, err := qrencode.New(value, qrencode.Medium)
	if err != nil {
		return "", err
	}
	return code.ToSmallString(false), nil
}
func PNG(public identity.Public, path string) error {
	value, err := Encode(public)
	if err != nil {
		return err
	}
	data, err := qrencode.Encode(value, qrencode.Medium, 512)
	if err != nil {
		return err
	}
	return fsutil.PublishAtomic(path, false, func(f *os.File) error { _, e := f.Write(data); return e })
}
func ImportPNG(path string) (identity.Public, error) {
	f, err := os.Open(path)
	if err != nil {
		return identity.Public{}, err
	}
	defer f.Close()
	imageData, _, err := image.Decode(f)
	if err != nil {
		return identity.Public{}, err
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(imageData)
	if err != nil {
		return identity.Public{}, err
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return identity.Public{}, fmt.Errorf("qr: decode image: %w", err)
	}
	return Decode(result.GetText())
}
