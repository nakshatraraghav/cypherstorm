package hashing_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/security/hashing"
)

func TestDigestSupportedAlgorithms(t *testing.T) {
	want := map[hashing.ID]string{
		hashing.SHA256: "917fef6f66440aa285be30f1e966e23d89fcd996eef86e82a3a222dae4a3d6be",
		hashing.SHA384: "d90135dfc5adc195e45bb27c2539f6286a5338453564257a30a74a8651a66cc679c9f327d7e88b9fa411703e951f4f39",
		hashing.SHA512: "c7526cc8f0a963dd61d2ec24ec568b098bf95109d7337e22605646c4c23825211e3e8b8d0efc13907f4bd81be7e20aa222667b2fd2f69a5c877a67dc8f923ca6",
	}
	for _, id := range hashing.AllIDs() {
		t.Run(string(id), func(t *testing.T) {
			sum, err := hashing.Digest(context.Background(), bytes.NewBufferString("cypherstorm"), id)
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if got := hex.EncodeToString(sum); got != want[id] {
				t.Fatalf("digest = %s, want %s", got, want[id])
			}
		})
	}
}

func TestDigestRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := hashing.Digest(context.Background(), bytes.NewReader(nil), "md5"); err == nil {
		t.Fatal("expected unsupported digest to fail")
	}
}

func TestDigestRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashing.Digest(ctx, bytes.NewBufferString("data"), hashing.SHA256); err == nil {
		t.Fatal("expected cancelled digest to fail")
	}
}
