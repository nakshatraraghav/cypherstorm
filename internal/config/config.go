package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const MaxSize = 1 << 20

type File struct {
	Version            int    `toml:"version" json:"version"`
	DefaultCompression string `toml:"default_compression" json:"default_compression"`
	DefaultCipher      string `toml:"default_cipher" json:"default_cipher"`
	DefaultRecordSize  string `toml:"default_record_size" json:"default_record_size"`
	DefaultProfile     string `toml:"default_profile" json:"default_profile"`
	DefaultDestination string `toml:"default_destination" json:"default_destination"`
	VerifyAfter        bool   `toml:"verify_after" json:"verify_after"`
}
type Policy struct {
	Name               string `json:"name"`
	Compression        string `json:"compression"`
	Cipher             string `json:"cipher"`
	RecordSize         uint32 `json:"record_size"`
	DefaultDestination string `json:"default_destination,omitempty"`
	VerifyAfter        bool   `json:"verify_after"`
	MaxEntries         int    `json:"max_entries"`
	MaxTotalBytes      int64  `json:"max_total_bytes"`
}

func Defaults() File {
	return File{Version: 1, DefaultCompression: "gzip", DefaultCipher: "aes-256-gcm", DefaultRecordSize: "64KiB", DefaultProfile: "balanced"}
}
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: locate user config directory: %w", err)
	}
	return filepath.Join(dir, "cypherstorm", "config.toml"), nil
}
func Load(path string) (File, error) {
	if path == "" {
		var err error
		path, err = Path()
		if err != nil {
			return File{}, err
		}
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return File{}, fmt.Errorf("config: open: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return File{}, err
	}
	if len(data) > MaxSize {
		return File{}, fmt.Errorf("config: file exceeds %d-byte limit", MaxSize)
	}
	cfg := Defaults()
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return File{}, fmt.Errorf("config: decode: %w", err)
	}
	if cfg.Version != 1 {
		return File{}, fmt.Errorf("config: unsupported version %d", cfg.Version)
	}
	if containsSecretKey(data) {
		return File{}, fmt.Errorf("config: secret-bearing keys are prohibited")
	}
	return cfg, nil
}
func containsSecretKey(data []byte) bool {
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return false
	}
	return containsSecretKeyValue(document)
}

func containsSecretKeyValue(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			switch strings.ToLower(key) {
			case "password", "raw_key", "private_key", "keychain_token":
				return true
			}
			if containsSecretKeyValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if containsSecretKeyValue(child) {
				return true
			}
		}
	}
	return false
}
func Profiles() map[string]Policy {
	return map[string]Policy{"fast": {Name: "fast", Compression: "lz4", Cipher: "xchacha20poly1305", RecordSize: 256 << 10, MaxEntries: 100000, MaxTotalBytes: 8 << 30}, "balanced": {Name: "balanced", Compression: "gzip", Cipher: "aes-256-gcm", RecordSize: 64 << 10, MaxEntries: 100000, MaxTotalBytes: 8 << 30}, "hardened": {Name: "hardened", Compression: "zstd", Cipher: "xchacha20poly1305", RecordSize: 64 << 10, VerifyAfter: true, MaxEntries: 100000, MaxTotalBytes: 4 << 30}, "untrusted": {Name: "untrusted", Compression: "gzip", Cipher: "aes-256-gcm", RecordSize: 32 << 10, VerifyAfter: true, MaxEntries: 10000, MaxTotalBytes: 1 << 30}}
}
func Resolve(cfg File, profile string) (Policy, error) {
	explicitProfile := profile != ""
	envProfile := os.Getenv("CYPHERSTORM_PROFILE")
	if profile == "" {
		if envProfile != "" {
			profile = envProfile
		} else {
			profile = cfg.DefaultProfile
		}
	}
	base, ok := Profiles()[profile]
	if !ok {
		return Policy{}, fmt.Errorf("config: unknown policy %q", profile)
	}
	if !explicitProfile && envProfile == "" {
		if cfg.DefaultCompression != "" {
			base.Compression = cfg.DefaultCompression
		}
		if cfg.DefaultCipher != "" {
			base.Cipher = cfg.DefaultCipher
		}
		if cfg.DefaultRecordSize != "" {
			recordSize, err := parseByteSize(cfg.DefaultRecordSize)
			if err != nil {
				return Policy{}, fmt.Errorf("config: default record size: %w", err)
			}
			base.RecordSize = recordSize
		}
		base.DefaultDestination = cfg.DefaultDestination
		if cfg.VerifyAfter {
			base.VerifyAfter = true
		}
	}
	if value := os.Getenv("CYPHERSTORM_COMPRESSION"); value != "" {
		base.Compression = value
	}
	if value := os.Getenv("CYPHERSTORM_CIPHER"); value != "" {
		base.Cipher = value
	}
	if value := os.Getenv("CYPHERSTORM_VERIFY_AFTER"); value == "1" || strings.EqualFold(value, "true") {
		base.VerifyAfter = true
	}
	return base, nil
}

func parseByteSize(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("size is empty")
	}
	multiplier := uint64(1)
	upper := strings.ToUpper(value)
	for _, unit := range []struct {
		suffix string
		factor uint64
	}{
		{suffix: "GIB", factor: 1 << 30},
		{suffix: "MIB", factor: 1 << 20},
		{suffix: "KIB", factor: 1 << 10},
		{suffix: "B", factor: 1},
	} {
		if strings.HasSuffix(upper, unit.suffix) {
			value = strings.TrimSpace(value[:len(value)-len(unit.suffix)])
			multiplier = unit.factor
			break
		}
	}
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || number == 0 || number > uint64(^uint32(0))/multiplier {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	size := number * multiplier
	if size > uint64(^uint32(0)) {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	return uint32(size), nil
}
