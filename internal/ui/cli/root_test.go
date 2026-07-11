package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
)

func cliTestService(t *testing.T) *app.Service {
	t.Helper()
	service, err := app.NewServiceWithConfig(app.Config{
		Argon2:     kdf.Argon2Params{Time: 1, MemoryKiB: 8, Parallelism: 1, KeyLength: kdf.MasterKeySize},
		RecordSize: 16,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	return service
}

func execute(t *testing.T, service Service, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := NewRoot(service, Streams{In: strings.NewReader(stdin), Out: &stdout, Err: &stderr}, "test-version")
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return stdout.String(), stderr.String(), err
}

func TestPasswordStdinProtectRestoreRoundTrip(t *testing.T) {
	service := cliTestService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("cli password round trip"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	protected := filepath.Join(root, "input.cys")
	stdout, _, err := execute(t, service, "secret password\n",
		"protect", "--input-path", input, "--output-path", protected, "--password-stdin",
	)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if !strings.Contains(stdout, protected) {
		t.Fatalf("protect output missing path: %q", stdout)
	}
	destination := filepath.Join(root, "restored")
	if _, _, err := execute(t, service, "secret password\n",
		"restore", "--input-path", protected, "--output-path", destination, "--password-stdin",
	); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, filepath.Base(input)))
	if err != nil || string(got) != "cli password round trip" {
		t.Fatalf("restored bytes = %q, err=%v", got, err)
	}
}

func TestRawKeyProtectRestoreRoundTrip(t *testing.T) {
	service := cliTestService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("raw key round trip"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	keyPath := filepath.Join(root, "key.bin")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x23}, kdf.MasterKeySize), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	protected := filepath.Join(root, "input.cys")
	if _, _, err := execute(t, service, "", "protect", "--input-path", input, "--output-path", protected, "--key-file", keyPath); err != nil {
		t.Fatalf("protect: %v", err)
	}
	destination := filepath.Join(root, "restored")
	if _, _, err := execute(t, service, "", "restore", "--input-path", protected, "--output-path", destination, "--key-file", keyPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, filepath.Base(input)))
	if err != nil || string(got) != "raw key round trip" {
		t.Fatalf("restored bytes = %q, err=%v", got, err)
	}
}

func TestHelpDoesNotExposePasswordArgument(t *testing.T) {
	service := cliTestService(t)
	stdout, _, err := execute(t, service, "", "protect", "--help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if strings.Contains(stdout, "--password ") || strings.Contains(stdout, "--password=") {
		t.Fatalf("help exposes password argument: %s", stdout)
	}
	if !strings.Contains(stdout, "--password-stdin") || !strings.Contains(stdout, "--key-file") {
		t.Fatalf("help missing secure credential options: %s", stdout)
	}
}

func TestNonInteractivePasswordRequiresExplicitSource(t *testing.T) {
	service := cliTestService(t)
	root := t.TempDir()
	input := filepath.Join(root, "input")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	_, _, err := execute(t, service, "", "protect", "--input-path", input, "--output-path", filepath.Join(root, "out"))
	if err == nil || !strings.Contains(err.Error(), "no interactive terminal") {
		t.Fatalf("expected noninteractive credential error, got %v", err)
	}
}

func TestTUIRoutingOnlyForBareInteractiveOrExplicitCommand(t *testing.T) {
	service := cliTestService(t)
	for _, test := range []struct {
		name        string
		interactive bool
		args        []string
		wantRuns    int
	}{
		{name: "bare noninteractive", interactive: false, wantRuns: 0},
		{name: "bare interactive", interactive: true, wantRuns: 1},
		{name: "explicit tui", interactive: true, args: []string{"tui"}, wantRuns: 1},
		{name: "root help", interactive: true, args: []string{"--help"}, wantRuns: 0},
		{name: "subcommand help", interactive: true, args: []string{"protect", "--help"}, wantRuns: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runs := 0
			root := NewRootWithOptions(
				service,
				Streams{In: strings.NewReader(""), Out: &stdout, Err: &stderr},
				"test",
				RootOptions{
					Interactive: test.interactive,
					RunTUI: func(context.Context) error {
						runs++
						return nil
					},
				},
			)
			root.SetArgs(test.args)
			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if runs != test.wantRuns {
				t.Fatalf("TUI runs = %d, want %d", runs, test.wantRuns)
			}
			if !test.interactive && len(test.args) == 0 && !strings.Contains(stdout.String(), "Available Commands:") {
				t.Fatalf("bare noninteractive output is not help: %s", stdout.String())
			}
		})
	}
}
