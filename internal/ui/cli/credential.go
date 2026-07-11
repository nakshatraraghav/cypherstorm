package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
	"golang.org/x/term"
)

const maxPasswordBytes = 1 << 20

func resolveCredential(streams Streams, keyFile string, passwordStdin, confirm bool) (app.Credential, error) {
	if keyFile != "" && passwordStdin {
		return app.Credential{}, fmt.Errorf("cli: --key-file and --password-stdin are mutually exclusive")
	}
	if keyFile != "" {
		key, err := readRawKeyFile(keyFile)
		if err != nil {
			return app.Credential{}, err
		}
		return app.Credential{Kind: app.CredentialRawKey, RawKey: key}, nil
	}
	if passwordStdin {
		password, err := readPasswordStream(streams.In)
		if err != nil {
			return app.Credential{}, err
		}
		return app.Credential{Kind: app.CredentialPassword, Password: password}, nil
	}

	password, err := readTerminalPassword(streams, "Password: ")
	if err != nil {
		return app.Credential{}, err
	}
	if confirm {
		confirmation, err := readTerminalPassword(streams, "Confirm password: ")
		if err != nil {
			clearBytes(password)
			return app.Credential{}, err
		}
		matches := bytes.Equal(password, confirmation)
		clearBytes(confirmation)
		if !matches {
			clearBytes(password)
			return app.Credential{}, fmt.Errorf("cli: password confirmation does not match")
		}
	}
	return app.Credential{Kind: app.CredentialPassword, Password: password}, nil
}

func readRawKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cli: inspect raw-key file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("cli: raw-key file %q must be a regular file, not a symlink", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("cli: raw-key file %q permissions %04o expose key material; require 0600 or stricter", path, info.Mode().Perm())
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cli: read raw-key file %q: %w", path, err)
	}
	if len(key) != kdf.MasterKeySize {
		clearBytes(key)
		return nil, fmt.Errorf("cli: raw-key file must contain exactly %d binary bytes, got %d", kdf.MasterKeySize, len(key))
	}
	return key, nil
}

func readPasswordStream(reader io.Reader) ([]byte, error) {
	password, err := io.ReadAll(io.LimitReader(reader, maxPasswordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cli: read password from stdin: %w", err)
	}
	if len(password) > maxPasswordBytes {
		clearBytes(password)
		return nil, fmt.Errorf("cli: password exceeds %d-byte limit", maxPasswordBytes)
	}
	password = bytes.TrimSuffix(password, []byte("\n"))
	password = bytes.TrimSuffix(password, []byte("\r"))
	if len(password) == 0 {
		return nil, fmt.Errorf("cli: password is empty")
	}
	return password, nil
}

func readTerminalPassword(streams Streams, prompt string) ([]byte, error) {
	input, ok := streams.In.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return nil, fmt.Errorf("cli: no interactive terminal available; use --password-stdin or --key-file")
	}
	if _, err := fmt.Fprint(streams.Err, prompt); err != nil {
		return nil, fmt.Errorf("cli: write password prompt: %w", err)
	}
	password, err := term.ReadPassword(int(input.Fd()))
	_, newlineErr := fmt.Fprintln(streams.Err)
	if err != nil {
		return nil, fmt.Errorf("cli: read password: %w", err)
	}
	if newlineErr != nil {
		clearBytes(password)
		return nil, fmt.Errorf("cli: finish password prompt: %w", newlineErr)
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("cli: password is empty")
	}
	return password, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
