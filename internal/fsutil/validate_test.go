package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

func TestValidateOutputTargetRejectsExistingWithoutOverwrite(t *testing.T) {
	dir := testutil.Workspace(t)
	path := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := ValidateOutputTarget(path, false); err == nil {
		t.Fatalf("expected error for existing output without overwrite")
	}
	if err := ValidateOutputTarget(path, true); err != nil {
		t.Fatalf("expected no error when overwrite allowed, got: %v", err)
	}
}

func TestValidateOutputTargetAcceptsCreatableParent(t *testing.T) {
	dir := testutil.Workspace(t)
	path := filepath.Join(dir, "nested", "deep", "out.bin")

	if err := ValidateOutputTarget(path, false); err != nil {
		t.Fatalf("expected creatable nested parent to validate, got: %v", err)
	}
}

func TestValidateOutputTargetRejectsFileAsParent(t *testing.T) {
	dir := testutil.Workspace(t)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}

	path := filepath.Join(blocker, "out.bin")
	if err := ValidateOutputTarget(path, false); err == nil {
		t.Fatalf("expected error when parent path component is a file")
	}
}

func TestValidateNoContainmentRejectsOutputInsideInput(t *testing.T) {
	dir := testutil.Workspace(t)
	input := filepath.Join(dir, "input")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}
	output := filepath.Join(input, "nested", "out.bin")

	if err := ValidateNoContainment(input, output); err == nil {
		t.Fatalf("expected error for output nested inside input")
	}
}

func TestValidateNoContainmentRejectsOutputEqualsInput(t *testing.T) {
	dir := testutil.Workspace(t)
	input := filepath.Join(dir, "input")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}

	if err := ValidateNoContainment(input, input); err == nil {
		t.Fatalf("expected error for output equal to input")
	}
	if err := ValidateNoContainment(input, input+string(filepath.Separator)); err == nil {
		t.Fatalf("expected error for output equal to input with trailing separator")
	}
}

func TestValidateNoContainmentAllowsSiblingOutput(t *testing.T) {
	dir := testutil.Workspace(t)
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output.bin")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}

	if err := ValidateNoContainment(input, output); err != nil {
		t.Fatalf("expected sibling output to validate, got: %v", err)
	}
}

func TestValidateNoContainmentAllowsInputInsideOutput(t *testing.T) {
	dir := testutil.Workspace(t)
	output := filepath.Join(dir, "output")
	input := filepath.Join(output, "nested", "in.bin")
	if err := os.MkdirAll(filepath.Dir(input), 0o700); err != nil {
		t.Fatalf("mkdir input parent: %v", err)
	}
	if err := os.WriteFile(input, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed input file: %v", err)
	}

	// output is an ancestor of input; that is not a "output inside input"
	// containment problem and must be allowed.
	if err := ValidateNoContainment(input, output); err != nil {
		t.Fatalf("expected output-as-ancestor to validate, got: %v", err)
	}
}
