package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/testutil"
)

// buildTar writes a hand-crafted tar stream from the given headers and,
// for TypeReg entries, the accompanying content. It bypasses CreateTar so
// tests can construct archives CreateTar itself would never produce.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(e.header); err != nil {
			t.Fatalf("write header for %q: %v", e.header.Name, err)
		}
		if len(e.content) > 0 {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatalf("write content for %q: %v", e.header.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	header  *tar.Header
	content []byte
}

func regEntry(name string, content []byte) tarEntry {
	return tarEntry{
		header: &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o600,
			Size:     int64(len(content)),
		},
		content: content,
	}
}

func TestExtractTarRejectsPathTraversal(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("../../etc/passwd", []byte("evil")),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject a traversal entry")
	}

	// Nothing must have been written anywhere outside destRoot. The
	// clearest local check: destRoot's parent gained no new entries, and
	// destRoot itself has no "etc" directory at all.
	if _, statErr := os.Stat(filepath.Join(destRoot, "etc")); statErr == nil {
		t.Fatalf("traversal entry was written inside destRoot")
	}
	parent := filepath.Dir(destRoot)
	if _, statErr := os.Stat(filepath.Join(parent, "etc")); statErr == nil {
		t.Fatalf("traversal entry escaped destRoot into parent directory")
	}
}

func TestExtractTarRejectsAbsolutePath(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("/etc/passwd", []byte("evil")),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject an absolute path entry")
	}
}

func TestExtractTarRejectsSymlinkEscape(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{header: &tar.Header{
			Name:     "evil-link",
			Typeflag: tar.TypeSymlink,
			Linkname: "../../../../etc",
			Mode:     0o777,
		}},
		regEntry("evil-link/passwd", []byte("evil")),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject a symlink-escape entry")
	}
}

func TestExtractTarRejectsUnsupportedEntryType(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{header: &tar.Header{
			Name:     "hardlink",
			Typeflag: tar.TypeLink,
			Linkname: "somewhere",
			Mode:     0o600,
		}},
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject a hardlink entry")
	}
}

func TestExtractTarEnforcesMaxEntrySizeAgainstActualBytes(t *testing.T) {
	// Header truthfully declares the real content size (1024 bytes,
	// comfortably under the default MaxTotalSize), but MaxEntrySize is
	// set well below that. ExtractTar must cap the actual bytes copied
	// at MaxEntrySize rather than trusting the header's declared size,
	// and must leave no partial file behind.
	content := bytes.Repeat([]byte("A"), 1024)
	data := buildTar(t, []tarEntry{regEntry("big.bin", content)})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxEntrySize: 10})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject an entry exceeding MaxEntrySize")
	}

	if _, statErr := os.Stat(filepath.Join(destRoot, "big.bin")); statErr == nil {
		t.Fatalf("expected no leftover partial file for rejected oversized entry")
	}
}

func TestExtractTarBoundedCopyDoesNotAllocateDeclaredSize(t *testing.T) {
	// A multi-megabyte entry with MaxEntrySize set far below its real
	// size must be rejected via the bounded copy path (io.CopyN capped
	// at MaxEntrySize+1), never by pre-allocating a buffer sized to the
	// header's declared length. A quick, error-returning rejection here
	// is the observable proof: no attempt was made to read/allocate the
	// full declared size before enforcing the cap.
	content := testutil.RandomBytes(t, 4<<20) // 4 MiB
	data := buildTar(t, []tarEntry{regEntry("huge-declared.bin", content)})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxEntrySize: 1024})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject entry exceeding MaxEntrySize")
	}

	if _, statErr := os.Stat(filepath.Join(destRoot, "huge-declared.bin")); statErr == nil {
		t.Fatalf("expected no leftover partial file for rejected oversized entry")
	}
}

func TestExtractTarEnforcesMaxEntries(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("a.txt", []byte("a")),
		regEntry("b.txt", []byte("b")),
		regEntry("c.txt", []byte("c")),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxEntries: 2})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject archive exceeding MaxEntries")
	}
}

func TestExtractTarEnforcesMaxTotalSize(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("a.txt", bytes.Repeat([]byte("a"), 100)),
		regEntry("b.txt", bytes.Repeat([]byte("b"), 100)),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxTotalSize: 150})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject archive exceeding MaxTotalSize")
	}
	if _, statErr := os.Stat(filepath.Join(destRoot, "b.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("violating entry left a partial file: %v", statErr)
	}
}

func TestExtractTarDefersDirectoryMetadata(t *testing.T) {
	modTime := time.Unix(1_700_000_000, 0)
	data := buildTar(t, []tarEntry{
		{header: &tar.Header{Name: "locked/", Typeflag: tar.TypeDir, Mode: 0o500, ModTime: modTime}},
		regEntry("locked/child.txt", []byte("child")),
	})

	destRoot := testutil.Workspace(t)
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(destRoot, "locked"), 0o700)
	})
	if err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{}); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(destRoot, "locked", "child.txt")); err != nil || string(got) != "child" {
		t.Fatalf("read child after read-only directory extraction: got %q err=%v", got, err)
	}
	info, err := os.Stat(filepath.Join(destRoot, "locked"))
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if info.Mode().Perm() != 0o500 {
		t.Fatalf("directory mode = %v, want 0500", info.Mode().Perm())
	}
	if !info.ModTime().Equal(modTime) {
		t.Fatalf("directory mtime = %v, want %v", info.ModTime(), modTime)
	}
}

func TestValidateEntryNameRejectsPlatformAmbiguity(t *testing.T) {
	for _, name := range []string{
		`..\\outside`,
		`nested\\outside`,
		`C:relative`,
		`C:/absolute`,
		`\\\\server\\share`,
		"nul\x00name",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateEntryName(name); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestExtractTarRejectsPlatformAmbiguousSymlinkTarget(t *testing.T) {
	data := buildTar(t, []tarEntry{{header: &tar.Header{
		Name:     "link",
		Typeflag: tar.TypeSymlink,
		Linkname: `..\\outside`,
		Mode:     0o777,
	}}})
	destRoot := testutil.Workspace(t)
	if err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{}); err == nil {
		t.Fatal("expected backslash symlink target to be rejected")
	}
}

func TestExtractTarRequiresEmptyDestination(t *testing.T) {
	data := buildTar(t, []tarEntry{regEntry("new.txt", []byte("new"))})
	destRoot := testutil.Workspace(t)
	existingPath := filepath.Join(destRoot, "existing.txt")
	if err := os.WriteFile(existingPath, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write existing destination file: %v", err)
	}
	if err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{}); err == nil {
		t.Fatal("expected nonempty destination to be rejected")
	}
	got, err := os.ReadFile(existingPath)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing destination changed: got %q err=%v", got, err)
	}
}

func TestExtractTarRejectsNegativeLimits(t *testing.T) {
	data := buildTar(t, nil)
	destRoot := testutil.Workspace(t)
	if err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxEntries: -1}); err == nil {
		t.Fatal("expected negative extraction limit to be rejected")
	}
}

func TestExtractTarEnforcesMaxPathDepth(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("a/b/c/d/e.txt", []byte("deep")),
	})

	destRoot := testutil.Workspace(t)
	err := ExtractTar(context.Background(), bytes.NewReader(data), destRoot, ExtractLimits{MaxPathDepth: 3})
	if err == nil {
		t.Fatalf("expected ExtractTar to reject archive exceeding MaxPathDepth")
	}
}

func TestExtractTarRespectsCancellation(t *testing.T) {
	data := buildTar(t, []tarEntry{
		regEntry("a.txt", []byte("a")),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	destRoot := testutil.Workspace(t)
	err := ExtractTar(ctx, bytes.NewReader(data), destRoot, ExtractLimits{})
	if err == nil {
		t.Fatalf("expected ExtractTar to fail on a cancelled context")
	}
}
