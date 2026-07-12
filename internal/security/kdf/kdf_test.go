package kdf

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestArgon2ParamsValidateBoundaries(t *testing.T) {
	validMinimum := Argon2Params{
		Time:        1,
		MemoryKiB:   8,
		Parallelism: 1,
		KeyLength:   MasterKeySize,
	}
	validMaximum := Argon2Params{
		Time:        MaxArgon2Time,
		MemoryKiB:   MaxArgon2MemoryKiB,
		Parallelism: MaxArgon2Parallelism,
		KeyLength:   MasterKeySize,
	}

	for name, params := range map[string]Argon2Params{
		"minimum": validMinimum,
		"maximum": validMaximum,
		"default": DefaultArgon2Params(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}

	tests := []struct {
		name   string
		params Argon2Params
		want   string
	}{
		{name: "zero time", params: Argon2Params{MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize}, want: "time parameter must be nonzero"},
		{name: "time above maximum", params: Argon2Params{Time: MaxArgon2Time + 1, MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize}, want: "time parameter"},
		{name: "zero memory", params: Argon2Params{Time: 1, Parallelism: 1, KeyLength: MasterKeySize}, want: "memory parameter must be nonzero"},
		{name: "memory above maximum", params: Argon2Params{Time: 1, MemoryKiB: MaxArgon2MemoryKiB + 1, Parallelism: 1, KeyLength: MasterKeySize}, want: "memory parameter"},
		{name: "zero parallelism", params: Argon2Params{Time: 1, MemoryKiB: 8, KeyLength: MasterKeySize}, want: "parallelism parameter must be nonzero"},
		{name: "parallelism above maximum", params: Argon2Params{Time: 1, MemoryKiB: 8 * uint32(MaxArgon2Parallelism+1), Parallelism: MaxArgon2Parallelism + 1, KeyLength: MasterKeySize}, want: "parallelism parameter"},
		{name: "insufficient memory per thread", params: Argon2Params{Time: 1, MemoryKiB: 15, Parallelism: 2, KeyLength: MasterKeySize}, want: "at least 8 KiB per parallel thread"},
		{name: "short key length", params: Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize - 1}, want: "exactly 32 bytes"},
		{name: "long key length", params: Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize + 1}, want: "exactly 32 bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.params.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestDeriveMasterKeyRejectsOutOfPolicyParameters(t *testing.T) {
	params := Argon2Params{
		Time:        1,
		MemoryKiB:   MaxArgon2MemoryKiB + 1,
		Parallelism: 1,
		KeyLength:   MasterKeySize,
	}
	_, err := DeriveMasterKey(
		context.Background(),
		Credential{Kind: SourcePassword, Password: []byte("password")},
		params,
		bytes.Repeat([]byte{1}, 32),
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected resource-policy error, got %v", err)
	}
}

func TestDeriveMasterKeyRawCredentialIsValidatedAndCopied(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, MasterKeySize)
	derived, err := DeriveMasterKey(context.Background(), Credential{Kind: SourceRaw, RawKey: raw}, Argon2Params{}, nil)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	if !bytes.Equal(derived, raw) {
		t.Fatal("derived raw master key mismatch")
	}
	derived[0] ^= 0xff
	if raw[0] != 7 {
		t.Fatal("DeriveMasterKey returned an alias of credential key material")
	}

	if _, err := DeriveMasterKey(context.Background(), Credential{Kind: SourceRaw, RawKey: raw[:MasterKeySize-1]}, Argon2Params{}, nil); err == nil {
		t.Fatal("expected short raw key to fail")
	}
}

func TestDeriveMasterKeyPasswordAndFileKeyDomainSeparation(t *testing.T) {
	params := Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize}
	salt := bytes.Repeat([]byte{3}, 32)
	credential := Credential{Kind: SourcePassword, Password: []byte("password")}
	first, err := DeriveMasterKey(context.Background(), credential, params, salt)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	second, err := DeriveMasterKey(context.Background(), credential, params, salt)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("Argon2 derivation is not deterministic: %x, %v", second, err)
	}
	a, err := DeriveFileKey(first, salt, "cypherstorm/test/a", MasterKeySize)
	if err != nil {
		t.Fatalf("DeriveFileKey a: %v", err)
	}
	b, err := DeriveFileKey(first, salt, "cypherstorm/test/b", MasterKeySize)
	if err != nil {
		t.Fatalf("DeriveFileKey b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("domain-separated file keys collided")
	}
}

func TestDeriveMasterKeyHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DeriveMasterKey(ctx, Credential{Kind: SourcePassword, Password: []byte("password")}, Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: MasterKeySize}, []byte("salt"))
	if err != context.Canceled {
		t.Fatalf("DeriveMasterKey cancelled context error = %v", err)
	}
}
