package archive

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

func TestCreateExtractRoundTrip(t *testing.T) {
	root := testutil.SourceTree(t, []testutil.SourceTreeFile{
		{RelPath: "a.txt", Content: []byte("hello world"), Mode: 0o640},
		{RelPath: "nested/b.txt", Content: testutil.RandomBytes(t, 4096), Mode: 0o600},
		{RelPath: "nested/deeper/c.txt", Content: []byte("c"), Mode: 0o644},
	})

	// Empty directory - SourceTree only creates dirs implied by files, so
	// add one explicitly.
	if err := os.MkdirAll(filepath.Join(root, "emptydir"), 0o750); err != nil {
		t.Fatalf("mkdir emptydir: %v", err)
	}

	// Symlink pointing at a sibling file.
	if err := os.Symlink("a.txt", filepath.Join(root, "link-to-a")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var buf bytes.Buffer
	if err := CreateTar(context.Background(), root, &buf); err != nil {
		t.Fatalf("CreateTar: %v", err)
	}

	destRoot := testutil.Workspace(t)
	if err := ExtractTar(context.Background(), &buf, destRoot, ExtractLimits{}); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}

	// Regular file bytes and mode.
	gotA, err := os.ReadFile(filepath.Join(destRoot, "a.txt"))
	if err != nil {
		t.Fatalf("read a.txt: %v", err)
	}
	if string(gotA) != "hello world" {
		t.Fatalf("a.txt content mismatch: got %q", gotA)
	}
	infoA, err := os.Lstat(filepath.Join(destRoot, "a.txt"))
	if err != nil {
		t.Fatalf("lstat a.txt: %v", err)
	}
	if infoA.Mode().Perm() != 0o640 {
		t.Fatalf("a.txt mode mismatch: got %v want 0640", infoA.Mode().Perm())
	}

	wantB, err := os.ReadFile(filepath.Join(root, "nested", "b.txt"))
	if err != nil {
		t.Fatalf("read source nested/b.txt: %v", err)
	}
	gotB, err := os.ReadFile(filepath.Join(destRoot, "nested", "b.txt"))
	if err != nil {
		t.Fatalf("read extracted nested/b.txt: %v", err)
	}
	if !bytes.Equal(gotB, wantB) {
		t.Fatalf("nested/b.txt content mismatch")
	}

	if _, err := os.ReadFile(filepath.Join(destRoot, "nested", "deeper", "c.txt")); err != nil {
		t.Fatalf("read nested/deeper/c.txt: %v", err)
	}

	// Empty directory restored.
	emptyInfo, err := os.Stat(filepath.Join(destRoot, "emptydir"))
	if err != nil {
		t.Fatalf("stat emptydir: %v", err)
	}
	if !emptyInfo.IsDir() {
		t.Fatalf("emptydir is not a directory")
	}

	// Symlink target restored exactly.
	linkInfo, err := os.Lstat(filepath.Join(destRoot, "link-to-a"))
	if err != nil {
		t.Fatalf("lstat link-to-a: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link-to-a is not a symlink")
	}
	target, err := os.Readlink(filepath.Join(destRoot, "link-to-a"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "a.txt" {
		t.Fatalf("symlink target mismatch: got %q want %q", target, "a.txt")
	}
}

func TestCreateExtractSingleFileRoot(t *testing.T) {
	sourceDir := testutil.Workspace(t)
	sourcePath := filepath.Join(sourceDir, "payload.txt")
	want := []byte("single-file payload")
	if err := os.WriteFile(sourcePath, want, 0o640); err != nil {
		t.Fatalf("write source: %v", err)
	}

	var buf bytes.Buffer
	if err := CreateTar(context.Background(), sourcePath, &buf); err != nil {
		t.Fatalf("CreateTar: %v", err)
	}

	destRoot := testutil.Workspace(t)
	if err := ExtractTar(context.Background(), &buf, destRoot, ExtractLimits{}); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destRoot, filepath.Base(sourcePath)))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("single-file content mismatch: got %q want %q", got, want)
	}
}

func TestCreateExtractRootSymlink(t *testing.T) {
	sourceDir := testutil.Workspace(t)
	linkPath := filepath.Join(sourceDir, "payload-link")
	if err := os.Symlink("target.txt", linkPath); err != nil {
		t.Fatalf("create source symlink: %v", err)
	}

	var buf bytes.Buffer
	if err := CreateTar(context.Background(), linkPath, &buf); err != nil {
		t.Fatalf("CreateTar: %v", err)
	}

	destRoot := testutil.Workspace(t)
	if err := ExtractTar(context.Background(), &buf, destRoot, ExtractLimits{}); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	extractedPath := filepath.Join(destRoot, filepath.Base(linkPath))
	info, err := os.Lstat(extractedPath)
	if err != nil {
		t.Fatalf("lstat extracted symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("extracted root is not a symlink")
	}
	target, err := os.Readlink(extractedPath)
	if err != nil {
		t.Fatalf("read extracted symlink: %v", err)
	}
	if target != "target.txt" {
		t.Fatalf("symlink target = %q, want %q", target, "target.txt")
	}
}

func TestCreateTarRejectsUnsupportedEntryType(t *testing.T) {
	// Unix domain socket paths are capped at sizeof(sockaddr_un.sun_path)
	// (~104 bytes on macOS/BSD), well under a typical t.TempDir() path,
	// so this test stages its own short-path directory directly under
	// os.TempDir() rather than using testutil.Workspace.
	root, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatalf("mkdir short temp root: %v", err)
	}
	defer os.RemoveAll(root)

	sockPath := filepath.Join(root, "s")
	ln, err := listenUnixSocket(sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket for test: %v", err)
	}
	defer ln.Close()

	var buf bytes.Buffer
	if err := CreateTar(context.Background(), root, &buf); err == nil {
		t.Fatalf("expected CreateTar to reject a socket entry")
	}
}

func TestCreateTarRespectsCancellation(t *testing.T) {
	root := testutil.SourceTree(t, []testutil.SourceTreeFile{
		{RelPath: "a.txt", Content: []byte("x")},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	err := CreateTar(ctx, root, &buf)
	if err == nil {
		t.Fatalf("expected CreateTar to fail on a cancelled context")
	}
}
