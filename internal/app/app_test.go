package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/nakshatraraghav/cypherstorm/internal/security/container"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/security/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/security/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
)

func testService(t *testing.T) *Service {
	t.Helper()
	service, err := NewServiceWithConfig(Config{
		Argon2:     kdf.Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: kdf.MasterKeySize},
		RecordSize: 16,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	return service
}

func passwordCredential() Credential {
	return Credential{Kind: CredentialPassword, Password: []byte("correct horse battery staple")}
}

func rawKeyCredential() Credential {
	return Credential{Kind: CredentialRawKey, RawKey: bytes.Repeat([]byte{0x42}, kdf.MasterKeySize)}
}

func TestProtectRestoreMatrix(t *testing.T) {
	service := testService(t)
	credentials := []struct {
		name       string
		credential Credential
	}{
		{name: "password", credential: passwordCredential()},
		{name: "raw-key", credential: rawKeyCredential()},
	}
	sizes := []int{0, 1, 16, 53}

	for _, codec := range compress.AllCodecs() {
		for _, cipherID := range crypto.AllCipherIDs() {
			for _, credential := range credentials {
				for _, size := range sizes {
					name := strings.Join([]string{string(codec.ID()), string(cipherID), credential.name, fmt.Sprint(size)}, "/")
					t.Run(name, func(t *testing.T) {
						root := t.TempDir()
						input := filepath.Join(root, "payload.bin")
						want := bytes.Repeat([]byte{byte(size + 1)}, size)
						if err := os.WriteFile(input, want, 0o640); err != nil {
							t.Fatalf("write input: %v", err)
						}
						protected := filepath.Join(root, "payload.cys")
						if _, err := service.Protect(context.Background(), ProtectRequest{
							InputPath: input, OutputPath: protected, Credential: credential.credential,
							Cipher: cipherID, Codec: codec.ID(),
						}, nil); err != nil {
							t.Fatalf("Protect: %v", err)
						}
						restored := filepath.Join(root, "restored")
						if _, err := service.Restore(context.Background(), RestoreRequest{
							InputPath: protected, OutputPath: restored, Credential: credential.credential,
						}, nil); err != nil {
							t.Fatalf("Restore: %v", err)
						}
						got, err := os.ReadFile(filepath.Join(restored, filepath.Base(input)))
						if err != nil {
							t.Fatalf("read restored: %v", err)
						}
						if !bytes.Equal(got, want) {
							t.Fatalf("restored bytes mismatch: got %d want %d", len(got), len(want))
						}
					})
				}
			}
		}
	}
}

func TestProtectUsesCanonicalV2AndRejectsLegacyFormat(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("canonical payload"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	protected := filepath.Join(root, "input.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: rawKeyCredential(),
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, nil); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	protectedBytes, err := os.ReadFile(protected)
	if err != nil {
		t.Fatalf("read protected output: %v", err)
	}
	if len(protectedBytes) < len(container.Magic) || !bytes.Equal(protectedBytes[:len(container.Magic)], container.Magic[:]) {
		t.Fatalf("protected output is not v2: %x", protectedBytes)
	}
	inspected, err := service.Inspect(context.Background(), InspectRequest{InputPath: protected}, nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if inspected.FormatVersion != container.Version {
		t.Fatalf("format version = %d, want %d", inspected.FormatVersion, container.Version)
	}

	legacy := filepath.Join(root, "legacy.cys")
	if err := os.WriteFile(legacy, []byte("CYPHRSTM"), 0o600); err != nil {
		t.Fatalf("write legacy marker: %v", err)
	}
	if _, err := service.Inspect(context.Background(), InspectRequest{InputPath: legacy}, nil); !errors.Is(err, ErrUnsupportedProtectedFormat) {
		t.Fatalf("Inspect legacy error = %v, want ErrUnsupportedProtectedFormat", err)
	}
}

func TestProtectRestoreDirectory(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "tree")
	if err := os.MkdirAll(filepath.Join(input, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}
	if err := os.WriteFile(filepath.Join(input, "a.txt"), []byte("alpha"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(input, "nested", "b.txt"), []byte("beta"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}
	protected := filepath.Join(root, "tree.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: passwordCredential(),
		Cipher: crypto.XChaCha20Poly1305, Codec: compress.CompressionZstd,
	}, nil); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	restored := filepath.Join(root, "restored")
	if _, err := service.Restore(context.Background(), RestoreRequest{
		InputPath: protected, OutputPath: restored, Credential: passwordCredential(),
	}, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for path, want := range map[string]string{"a.txt": "alpha", "nested/b.txt": "beta"} {
		got, err := os.ReadFile(filepath.Join(restored, filepath.FromSlash(path)))
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, err=%v", path, got, err)
		}
	}
}

func TestBenchmarkRunsDeterministicCompleteMatrix(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("benchmark payload"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	output := filepath.Join(root, "benchmark.xlsx")
	result, err := service.Benchmark(context.Background(), BenchmarkRequest{InputPath: input, OutputPath: output}, nil)
	if err != nil {
		t.Fatalf("Benchmark: %v", err)
	}
	want := report.AllCombinations()
	if len(result.Successes) != len(want) || len(result.Failures) != 0 {
		t.Fatalf("benchmark successes=%d failures=%d, want %d/0", len(result.Successes), len(result.Failures), len(want))
	}
	for index, combination := range want {
		if result.Successes[index].Combination != combination {
			t.Fatalf("benchmark order[%d] = %+v, want %+v", index, result.Successes[index].Combination, combination)
		}
	}
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("benchmark report missing or empty: info=%v err=%v", info, err)
	}
}

func TestBenchmarkAllFailuresReturnsCompleteReport(t *testing.T) {
	service := testService(t)
	sentinel := errors.New("simulated combination failure")
	service.benchmarkRunner = func(context.Context, string, report.Combination) (int64, error) {
		return 0, sentinel
	}
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("benchmark payload"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	output := filepath.Join(root, "failed-benchmark.xlsx")
	result, err := service.Benchmark(context.Background(), BenchmarkRequest{InputPath: input, OutputPath: output}, nil)
	if !errors.Is(err, ErrNoBenchmarkSuccess) {
		t.Fatalf("Benchmark error = %v, want ErrNoBenchmarkSuccess", err)
	}
	if len(result.Successes) != 0 || len(result.Failures) != len(report.AllCombinations()) {
		t.Fatalf("all-failure report successes=%d failures=%d", len(result.Successes), len(result.Failures))
	}
	for _, failure := range result.Failures {
		if !errors.Is(failure.Err, sentinel) {
			t.Fatalf("failure lost cause: %v", failure.Err)
		}
	}
	if info, statErr := os.Stat(output); statErr != nil || info.Size() == 0 {
		t.Fatalf("all-failure report not published: info=%v err=%v", info, statErr)
	}
}

func TestRestoreWrongCredentialAndExistingDestinationPublishNothing(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	protected := filepath.Join(root, "input.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: passwordCredential(),
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, nil); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	wrongDestination := filepath.Join(root, "wrong")
	if _, err := service.Restore(context.Background(), RestoreRequest{
		InputPath:  protected,
		OutputPath: wrongDestination,
		Credential: Credential{Kind: CredentialPassword, Password: []byte("wrong")},
	}, nil); err == nil {
		t.Fatal("expected wrong password to fail")
	}
	if _, err := os.Stat(wrongDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-password restore published destination: %v", err)
	}

	existingDestination := filepath.Join(root, "existing")
	if err := os.Mkdir(existingDestination, 0o700); err != nil {
		t.Fatalf("mkdir existing destination: %v", err)
	}
	sentinel := filepath.Join(existingDestination, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if _, err := service.Restore(context.Background(), RestoreRequest{
		InputPath: protected, OutputPath: existingDestination, Credential: passwordCredential(),
	}, nil); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing destination changed: got %q err=%v", got, err)
	}
}

func TestRestoreFailurePublishesNothing(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	protected := filepath.Join(root, "input.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: passwordCredential(),
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, nil); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	container, err := os.ReadFile(protected)
	if err != nil {
		t.Fatalf("read protected: %v", err)
	}
	container[len(container)-1] ^= 0xff
	if err := os.WriteFile(protected, container, 0o600); err != nil {
		t.Fatalf("tamper protected: %v", err)
	}
	destination := filepath.Join(root, "restored")
	if _, err := service.Restore(context.Background(), RestoreRequest{
		InputPath: protected, OutputPath: destination, Credential: passwordCredential(),
	}, nil); err == nil {
		t.Fatal("expected tampered restore to fail")
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore published destination: %v", err)
	}
}

func TestCancellationPreservesExistingOutputAndCleansRestoreStage(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, bytes.Repeat([]byte("data"), 128), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	output := filepath.Join(root, "output.cys")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := service.Protect(ctx, ProtectRequest{
		InputPath: input, OutputPath: output, Credential: rawKeyCredential(), Overwrite: true,
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, func(event Event) {
		if event.Phase == PhaseEncrypting {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Protect cancellation error = %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing output changed: got %q err=%v", got, err)
	}

	protected := filepath.Join(root, "valid.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: rawKeyCredential(),
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, nil); err != nil {
		t.Fatalf("Protect valid: %v", err)
	}
	restoreCtx, restoreCancel := context.WithCancel(context.Background())
	destination := filepath.Join(root, "restored")
	_, err = service.Restore(restoreCtx, RestoreRequest{
		InputPath: protected, OutputPath: destination, Credential: rawKeyCredential(),
	}, func(event Event) {
		if event.Phase == PhaseExtracting {
			restoreCancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Restore cancellation error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled restore published destination: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read operation root: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cypherstorm-restore-") {
			t.Fatalf("restore staging directory was not removed: %s", entry.Name())
		}
	}
}

func TestCancellationAtEveryPipelineStagePublishesNothing(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, bytes.Repeat([]byte("stage cancellation"), 1024), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	for _, phase := range []Phase{PhaseArchiving, PhaseCompressing, PhaseEncrypting} {
		t.Run("protect-"+string(phase), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			output := filepath.Join(root, "cancel-"+string(phase)+".cys")
			_, err := service.Protect(ctx, ProtectRequest{
				InputPath: input, OutputPath: output, Credential: rawKeyCredential(),
				Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
			}, func(event Event) {
				if event.Phase == phase {
					cancel()
				}
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cancelled protect published output: %v", err)
			}
		})
	}

	protected := filepath.Join(root, "valid.cys")
	if _, err := service.Protect(context.Background(), ProtectRequest{
		InputPath: input, OutputPath: protected, Credential: rawKeyCredential(),
		Cipher: crypto.AES256GCM, Codec: compress.CompressionGzip,
	}, nil); err != nil {
		t.Fatalf("Protect valid: %v", err)
	}
	for _, phase := range []Phase{PhaseDecrypting, PhaseDecompressing, PhaseExtracting} {
		t.Run("restore-"+string(phase), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			destination := filepath.Join(root, "cancel-"+string(phase))
			_, err := service.Restore(ctx, RestoreRequest{
				InputPath: protected, OutputPath: destination, Credential: rawKeyCredential(),
			}, func(event Event) {
				if event.Phase == phase {
					cancel()
				}
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cancelled restore published destination: %v", err)
			}
		})
	}
}

func TestHashStructuredTraversalSkipsSymlinks(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	results, err := service.Hash(context.Background(), HashRequest{InputPath: root, Algorithm: hashing.SHA256}, nil)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(results) != 2 || results[0].Path != "a.txt" || results[1].Path != "b.txt" {
		t.Fatalf("unexpected hash results: %+v", results)
	}
	if len(results[0].Digest) != 32 {
		t.Fatalf("SHA-256 digest length = %d", len(results[0].Digest))
	}
}

func TestConcurrentProtectOperationsAreIndependent(t *testing.T) {
	service := testService(t)
	root := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			input := filepath.Join(root, fmt.Sprintf("input-%d.txt", i))
			output := filepath.Join(root, fmt.Sprintf("output-%d.cys", i))
			if err := os.WriteFile(input, []byte(fmt.Sprintf("payload-%d", i)), 0o600); err != nil {
				errs <- err
				return
			}
			_, err := service.Protect(context.Background(), ProtectRequest{
				InputPath: input, OutputPath: output, Credential: rawKeyCredential(),
				Cipher: crypto.XChaCha20Poly1305, Codec: compress.CompressionLZ4,
			}, nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Protect: %v", err)
		}
	}
}
