package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
)

const maxIdentitySize = 1 << 20
const signatureDomain = "cypherstorm/detached-signature/v1\x00"

type Private struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Secret  string `json:"secret"`
}
type Public struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Key     string `json:"key"`
	Label   string `json:"label,omitempty"`
}
type Signature struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Label     string `json:"label,omitempty"`
}

func Generate(kind, path string) error {
	var p Private
	switch kind {
	case "signing":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		p = Private{1, kind, base64.StdEncoding.EncodeToString(priv)}
	case "x25519":
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		p = Private{1, kind, id.String()}
	default:
		return fmt.Errorf("identity: unsupported type %q", kind)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return fsutil.PublishAtomic(path, false, func(f *os.File) error {
		if err := f.Chmod(0o600); err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	})
}
func PublicFromPrivate(path string) (Public, error) {
	p, err := loadPrivate(path)
	if err != nil {
		return Public{}, err
	}
	switch p.Type {
	case "signing":
		raw, err := base64.StdEncoding.DecodeString(p.Secret)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return Public{}, fmt.Errorf("identity: malformed signing key")
		}
		pub := ed25519.PrivateKey(raw).Public().(ed25519.PublicKey)
		return Public{Version: 1, Type: "signing", Key: base64.StdEncoding.EncodeToString(pub)}, nil
	case "x25519":
		id, err := age.ParseX25519Identity(p.Secret)
		if err != nil {
			return Public{}, fmt.Errorf("identity: malformed x25519 key: %w", err)
		}
		return Public{Version: 1, Type: "x25519", Key: id.Recipient().String()}, nil
	default:
		return Public{}, fmt.Errorf("identity: unsupported type")
	}
}
func WritePublic(public Public, path string) error {
	data, err := json.Marshal(public)
	if err != nil {
		return err
	}
	return fsutil.PublishAtomic(path, false, func(f *os.File) error { _, err = f.Write(data); return err })
}
func LoadPublic(path string) (Public, error) {
	data, err := boundedRead(path)
	if err != nil {
		return Public{}, err
	}
	var p Public
	if err = json.Unmarshal(data, &p); err != nil {
		return Public{}, fmt.Errorf("identity: parse public key: %w", err)
	}
	if p.Version != 1 || (p.Type != "signing" && p.Type != "x25519") || len(p.Key) > 4096 || len(p.Label) > 256 {
		return Public{}, fmt.Errorf("identity: invalid public identity")
	}
	return p, nil
}
func Fingerprint(p Public) (string, error) {
	if p.Key == "" {
		return "", fmt.Errorf("identity: empty public key")
	}
	h := sha256.Sum256(append([]byte("cypherstorm/"+p.Type+"-fingerprint/v1\x00"), []byte(p.Key)...))
	x := hex.EncodeToString(h[:8])
	return fmt.Sprintf("cys-id:%s:%s:%s:%s", x[:4], x[4:8], x[8:12], x[12:16]), nil
}
func Sign(input, privatePath, output, label string) error {
	if len(label) > 256 {
		return fmt.Errorf("signature: label exceeds 256 bytes")
	}
	p, err := loadPrivate(privatePath)
	if err != nil {
		return err
	}
	if p.Type != "signing" {
		return fmt.Errorf("signature: signing identity required")
	}
	raw, err := base64.StdEncoding.DecodeString(p.Secret)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return fmt.Errorf("signature: malformed signing identity")
	}
	digest, err := fileDigest(input)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(raw), digest)
	pub := ed25519.PrivateKey(raw).Public().(ed25519.PublicKey)
	record := Signature{1, "ed25519", base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(sig), label}
	data, _ := json.Marshal(record)
	return fsutil.PublishAtomic(output, false, func(f *os.File) error { _, e := f.Write(data); return e })
}
func InspectSignature(path string) (Signature, error) {
	data, err := boundedRead(path)
	if err != nil {
		return Signature{}, err
	}
	var s Signature
	if err = json.Unmarshal(data, &s); err != nil {
		return Signature{}, err
	}
	pub, e1 := base64.StdEncoding.DecodeString(s.PublicKey)
	sig, e2 := base64.StdEncoding.DecodeString(s.Signature)
	if s.Version != 1 || s.Algorithm != "ed25519" || e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || len(s.Label) > 256 {
		return Signature{}, fmt.Errorf("signature: malformed detached signature")
	}
	return s, nil
}

// Verify checks that signaturePath authenticates input and that its signer
// is the explicitly trusted public identity or fingerprint in trustedSigner.
// It returns the authenticated signer fingerprint on success.
func Verify(input, signaturePath, trustedSigner string) (string, error) {
	if strings.TrimSpace(trustedSigner) == "" {
		return "", fmt.Errorf("signature: trusted signer is required")
	}
	s, err := InspectSignature(signaturePath)
	if err != nil {
		return "", err
	}
	actual := Public{Version: 1, Type: "signing", Key: s.PublicKey}
	actualFingerprint, err := Fingerprint(actual)
	if err != nil {
		return "", err
	}
	expectedFingerprint, err := trustedSignerFingerprint(trustedSigner)
	if err != nil {
		return "", err
	}
	if actualFingerprint != expectedFingerprint {
		return "", fmt.Errorf("signature: signer fingerprint %s does not match trusted signer %s", actualFingerprint, expectedFingerprint)
	}
	pub, _ := base64.StdEncoding.DecodeString(s.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(s.Signature)
	digest, err := fileDigest(input)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, digest, sig) {
		return "", fmt.Errorf("signature: verification failed")
	}
	return actualFingerprint, nil
}
func trustedSignerFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "cys-id:") {
		return value, nil
	}
	public, err := LoadPublic(value)
	if err != nil {
		return "", fmt.Errorf("signature: load trusted signer: %w", err)
	}
	if public.Type != "signing" {
		return "", fmt.Errorf("signature: trusted signing public identity required")
	}
	return Fingerprint(public)
}
func ParseX25519Private(path string) (age.Identity, error) {
	p, err := loadPrivate(path)
	if err != nil {
		return nil, err
	}
	if p.Type != "x25519" {
		return nil, fmt.Errorf("identity: x25519 identity required")
	}
	return age.ParseX25519Identity(p.Secret)
}
func ParseX25519Recipient(p Public) (age.Recipient, error) {
	if p.Type != "x25519" {
		return nil, fmt.Errorf("identity: x25519 public identity required")
	}
	return age.ParseX25519Recipient(p.Key)
}
func loadPrivate(path string) (Private, error) {
	f, err := os.Open(path)
	if err != nil {
		return Private{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Private{}, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return Private{}, err
	}
	if !info.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return Private{}, fmt.Errorf("identity: private identity must be a stable regular file")
	}
	data, err := boundedReadFrom(f)
	if err != nil {
		return Private{}, err
	}
	var p Private
	if err = json.Unmarshal(data, &p); err != nil {
		return Private{}, err
	}
	if p.Version != 1 || len(p.Secret) > 8192 {
		return Private{}, fmt.Errorf("identity: malformed private identity")
	}
	return p, nil
}

func boundedRead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return boundedReadFrom(f)
}

func boundedReadFrom(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxIdentitySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIdentitySize {
		return nil, fmt.Errorf("identity: input exceeds size limit")
	}
	return data, nil
}
func fileDigest(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	_, _ = h.Write([]byte(signatureDomain))
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
func EncodePublic(p Public) (string, error) {
	data, err := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(data), err
}
func DecodePublic(value string) (Public, error) {
	if len(value) > 16384 {
		return Public{}, fmt.Errorf("identity: encoded public identity too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return Public{}, err
	}
	var p Public
	if err = json.Unmarshal(data, &p); err != nil {
		return Public{}, err
	}
	if p.Version != 1 || p.Type != "x25519" {
		return Public{}, fmt.Errorf("identity: unsupported imported identity")
	}
	return p, nil
}
