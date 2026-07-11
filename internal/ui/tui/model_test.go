package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
)

type fakeService struct {
	protectResult app.ProtectResult
	protectErr    error
	restoreResult app.RestoreResult
	restoreErr    error
	hashResult    []app.HashResult
	hashErr       error
	benchmark     report.Report
	benchmarkErr  error
}

func (f *fakeService) Protect(_ context.Context, _ app.ProtectRequest, _ app.EventSink) (app.ProtectResult, error) {
	return f.protectResult, f.protectErr
}
func (f *fakeService) Restore(_ context.Context, _ app.RestoreRequest, _ app.EventSink) (app.RestoreResult, error) {
	return f.restoreResult, f.restoreErr
}
func (f *fakeService) Hash(_ context.Context, _ app.HashRequest, _ app.EventSink) ([]app.HashResult, error) {
	return f.hashResult, f.hashErr
}
func (f *fakeService) Benchmark(_ context.Context, _ app.BenchmarkRequest, _ app.EventSink) (report.Report, error) {
	return f.benchmark, f.benchmarkErr
}

func key(value string) tea.KeyMsg {
	switch value {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}
	}
}

func updateModel(t *testing.T, model Model, message tea.Msg) Model {
	t.Helper()
	updated, _ := model.Update(message)
	result, ok := updated.(Model)
	if !ok {
		t.Fatalf("Update returned %T", updated)
	}
	return result
}

func TestHomeNavigationReachesEveryForm(t *testing.T) {
	want := []screen{screenProtect, screenRestore, screenHash, screenBenchmark, screenHelp}
	for index, expected := range want {
		model := NewModel(&fakeService{})
		for range index {
			model = updateModel(t, model, key("down"))
		}
		model = updateModel(t, model, key("enter"))
		if model.screen != expected {
			t.Fatalf("menu %d reached screen %d, want %d", index, model.screen, expected)
		}
	}
}

func TestPickerSelectsFilesAndCurrentFoldersWithoutTypingPaths(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "sample.cys")
	if err := os.WriteFile(protected, []byte("container"), 0o600); err != nil {
		t.Fatalf("write protected file: %v", err)
	}

	model := NewModel(&fakeService{})
	model.screen = screenRestore
	model.restore.inputPath = protected
	updated, command := model.Update(key("enter"))
	model = updated.(Model)
	if model.screen != screenPicker || model.picker == nil {
		t.Fatal("source control did not open the file picker")
	}
	if !model.picker.model.FileAllowed || model.picker.model.DirAllowed {
		t.Fatal("restore source picker must accept protected files only")
	}
	model.restore.inputPath = ""
	if command == nil {
		t.Fatal("file picker did not request a directory listing")
	}
	model = updateModel(t, model, key("down"))
	if model.picker == nil || model.picker.ready {
		t.Fatal("picker accepted navigation before its directory listing was ready")
	}
	model = updateModel(t, model, command())
	model = updateModel(t, model, key("enter"))
	if model.screen != screenRestore || model.restore.inputPath != protected {
		t.Fatalf("selected source = %q, screen=%d", model.restore.inputPath, model.screen)
	}

	model.restore.focus = 1
	model.restore.syncFocus()
	updated, command = model.Update(key("enter"))
	model = updated.(Model)
	if model.screen != screenPicker || model.picker == nil || !model.picker.directories || model.picker.model.FileAllowed {
		t.Fatal("destination control did not open a folder-only picker")
	}
	if command == nil {
		t.Fatal("destination picker did not request a directory listing")
	}
	model = updateModel(t, model, command())
	model.picker.model.CurrentDirectory = root
	model = updateModel(t, model, key("s"))
	if model.screen != screenRestore || model.restore.outputDir != root {
		t.Fatalf("selected destination = %q, screen=%d", model.restore.outputDir, model.screen)
	}
	if got, want := model.restore.outputPreview(), filepath.Join(root, "sample-restored"); got != want {
		t.Fatalf("derived restore destination = %q, want %q", got, want)
	}
}

func TestCompressionAndEncryptionControlsOpenDropdowns(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenProtect
	for index, slot := range model.protect.slots() {
		if slot == slotCodec {
			model.protect.focus = index
			break
		}
	}
	model.protect.syncFocus()
	model = updateModel(t, model, key("enter"))
	if model.screen != screenDropdown || model.dropdown == nil || model.dropdown.title != "Compression" {
		t.Fatal("compression control did not open a dropdown")
	}
	if len(model.dropdown.options) < 2 {
		t.Fatal("compression dropdown has no selectable alternatives")
	}
	model = updateModel(t, model, key("down"))
	model = updateModel(t, model, key("enter"))
	if model.screen != screenProtect || model.protect.codecIndex != 1 {
		t.Fatalf("compression dropdown selected index %d", model.protect.codecIndex)
	}

	for index, slot := range model.protect.slots() {
		if slot == slotCipher {
			model.protect.focus = index
			break
		}
	}
	model = updateModel(t, model, key("enter"))
	if model.screen != screenDropdown || model.dropdown == nil || model.dropdown.title != "Encryption" {
		t.Fatal("encryption control did not open a dropdown")
	}
}

func TestProtectVisibleFocusOrderAndCredentialSwitch(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenProtect
	model.protect.password.SetValue("do-not-render")
	model.protect.confirmation.SetValue("do-not-render")
	model.protect.focus = 2
	model.protect.syncFocus()

	model = updateModel(t, model, key("enter"))
	if model.screen != screenDropdown || model.dropdown == nil || model.dropdown.title != "Credential" {
		t.Fatal("credential control did not open a dropdown")
	}
	model = updateModel(t, model, key("down"))
	model = updateModel(t, model, key("enter"))
	if model.protect.credential != app.CredentialRawKey {
		t.Fatal("credential dropdown did not select raw key")
	}
	if model.protect.password.Value() != "" || model.protect.confirmation.Value() != "" {
		t.Fatal("password buffers were not cleared when switching credential kind")
	}
	if got := model.protect.slots(); len(got) != 8 || got[3] != slotKeyFile {
		t.Fatalf("raw-key visible slots = %v", got)
	}
	model.protect.keyFilePath = "key.bin"
	model.protect.focus = 2
	model = updateModel(t, model, key("enter"))
	model = updateModel(t, model, key("up"))
	model = updateModel(t, model, key("enter"))
	if model.protect.credential != app.CredentialPassword || model.protect.keyFilePath != "" {
		t.Fatal("inactive key-file selection was not cleared")
	}

	model.protect.focus = 0
	model.protect.syncFocus()
	model = updateModel(t, model, key("tab"))
	if model.protect.focus != 1 {
		t.Fatalf("Tab focus = %d, want 1", model.protect.focus)
	}
	model = updateModel(t, model, key("shift+tab"))
	if model.protect.focus != 0 {
		t.Fatalf("Shift+Tab focus = %d, want 0", model.protect.focus)
	}
}

func TestProtectRejectsEmptyAndMismatchedPasswords(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	model := NewModel(&fakeService{})
	model.screen = screenProtect
	model.protect.inputPath = input
	model.protect.outputDir = root
	model.protect.focus = len(model.protect.slots()) - 1
	model.protect.syncFocus()
	model = updateModel(t, model, key("enter"))
	if model.screen != screenProtect || !strings.Contains(model.validation, "password is required") {
		t.Fatalf("empty password validation: screen=%d error=%q", model.screen, model.validation)
	}
	model.protect.password.SetValue("first")
	model.protect.confirmation.SetValue("second")
	model = updateModel(t, model, key("enter"))
	if !strings.Contains(model.validation, "does not match") {
		t.Fatalf("mismatch validation = %q", model.validation)
	}
}

func TestRestoreFormHasNoCipherOrCompressionControls(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenRestore
	view := model.View()
	if strings.Contains(view, "Cipher") || strings.Contains(view, "Compression") {
		t.Fatalf("restore view exposes protect-only controls:\n%s", view)
	}
}

func TestServiceErrorAndSuccessTransitions(t *testing.T) {
	sentinel := errors.New("simulated failure")
	service := &fakeService{protectErr: sentinel}
	model := NewModel(service)
	model.screen = screenRunning
	model.pendingKind = operationProtect
	model.operationID = 7
	model.protect.inputPath = "nonsecret-input"
	model = updateModel(t, model, operationDoneMsg{operationID: 7, kind: operationProtect, err: sentinel})
	if model.screen != screenError || !errors.Is(model.lastError, sentinel) {
		t.Fatalf("error transition: screen=%d error=%v", model.screen, model.lastError)
	}
	model = updateModel(t, model, key("enter"))
	if model.screen != screenProtect || model.protect.inputPath != "nonsecret-input" {
		t.Fatal("error return did not preserve nonsecret form context")
	}

	model.screen = screenRunning
	model.operationID = 8
	model = updateModel(t, model, operationDoneMsg{operationID: 8, kind: operationProtect, value: app.ProtectResult{OutputPath: "result.cys", OutputBytes: 42}})
	if model.screen != screenResult || !strings.Contains(model.View(), "result.cys") {
		t.Fatalf("success transition failed: screen=%d view=%s", model.screen, model.View())
	}
}

func TestBenchmarkFailureReportRendersWithoutPanic(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenRunning
	model.pendingKind = operationBenchmark
	model.operationID = 9
	failure := report.Failure{Err: errors.New("all combinations failed")}
	model = updateModel(t, model, operationDoneMsg{
		operationID: 9,
		kind:        operationBenchmark,
		value:       report.Report{Failures: []report.Failure{failure}},
		err:         errors.New("zero successes"),
		outputPath:  "benchmark.xlsx",
	})
	view := model.View()
	if model.screen != screenResult || !strings.Contains(view, "Benchmark completed with errors") || !strings.Contains(view, "benchmark.xlsx") {
		t.Fatalf("benchmark failure report not rendered: screen=%d view=%s", model.screen, view)
	}
}

func TestCancellationRunsOnceAndStaleMessagesAreIgnored(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenRunning
	model.operationID = 12
	cancelCount := 0
	model.cancel = func() { cancelCount++ }
	model = updateModel(t, model, key("esc"))
	model = updateModel(t, model, key("ctrl+c"))
	if cancelCount != 1 || !model.cancelRequested {
		t.Fatalf("cancel count=%d requested=%t", cancelCount, model.cancelRequested)
	}
	model = updateModel(t, model, operationDoneMsg{operationID: 11, kind: operationProtect, value: app.ProtectResult{OutputPath: "stale"}})
	if model.screen != screenRunning {
		t.Fatal("stale completion changed active screen")
	}
	model = updateModel(t, model, progressMsg{operationID: 11, event: app.Event{Phase: app.PhaseComplete}})
	if model.progress.Phase == app.PhaseComplete {
		t.Fatal("stale progress changed active operation")
	}
}

func TestResizePreservesFieldsAndShowsMinimumSizeMessage(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenProtect
	model.protect.inputPath = "keep-this-path"
	model = updateModel(t, model, tea.WindowSizeMsg{Width: 40, Height: 8})
	if model.protect.inputPath != "keep-this-path" {
		t.Fatal("resize lost field value")
	}
	if !strings.Contains(model.View(), "too small") {
		t.Fatalf("narrow layout missing minimum-size message: %s", model.View())
	}
	model = updateModel(t, model, tea.WindowSizeMsg{Width: 100, Height: 30})
	if !strings.Contains(model.View(), "keep-this-path") {
		t.Fatal("resized form did not preserve visible value")
	}
}

func TestSecretsAreAbsentFromViewsAndDebugFormatting(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenProtect
	secret := "unique-secret-value"
	model.protect.password.SetValue(secret)
	model.protect.confirmation.SetValue(secret)
	if strings.Contains(model.View(), secret) {
		t.Fatal("secret appeared in rendered view")
	}
	if strings.Contains(fmt.Sprintf("%+v", model), secret) {
		t.Fatal("secret appeared in debug formatting")
	}
	model = updateModel(t, model, key("esc"))
	if model.protect.password.Value() != "" || model.protect.confirmation.Value() != "" {
		t.Fatal("leaving form did not clear secret buffers")
	}
}
