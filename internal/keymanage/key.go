package keymanage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"

	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
)

const fingerprintDomain = "cypherstorm/raw-key-fingerprint/v1\x00"

func Generate(path string) error {
	key := make([]byte, kdf.MasterKeySize)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("key: generate random bytes: %w", err)
	}
	return fsutil.PublishAtomic(path, false, func(f *os.File) error {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("key: restrict permissions: %w", err)
		}
		if _, err := f.Write(key); err != nil {
			return fmt.Errorf("key: write: %w", err)
		}
		return nil
	})
}

func Load(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("key: inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key: %q must be a regular non-symlink file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key: permissions %04o expose key material; require 0600 or stricter", info.Mode().Perm())
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("key: read %q: %w", path, err)
	}
	if len(key) != kdf.MasterKeySize {
		clear(key)
		return nil, fmt.Errorf("key: expected exactly %d bytes, got %d", kdf.MasterKeySize, len(key))
	}
	return key, nil
}

func Fingerprint(key []byte) (string, error) {
	if len(key) != kdf.MasterKeySize {
		return "", fmt.Errorf("key: expected exactly %d bytes", kdf.MasterKeySize)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(fingerprintDomain))
	_, _ = h.Write(key)
	sum := h.Sum(nil)
	x := hex.EncodeToString(sum[:8])
	return fmt.Sprintf("cys-key:%s:%s:%s:%s", x[0:4], x[4:8], x[8:12], x[12:16]), nil
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
