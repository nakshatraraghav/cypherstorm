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
func (f *fakeService) Inspect(_ context.Context, _ app.InspectRequest, _ app.EventSink) (app.InspectResult, error) {
	return app.InspectResult{}, nil
}
func (f *fakeService) Verify(_ context.Context, _ app.VerifyRequest, _ app.EventSink) (app.VerifyResult, error) {
	return app.VerifyResult{}, nil
}
func (f *fakeService) List(_ context.Context, _ app.ListRequest, _ app.EventSink) (app.ListResult, error) {
	return app.ListResult{}, nil
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

func runCommand(t *testing.T, model Model, command tea.Cmd) Model {
	t.Helper()
	if command == nil {
		return model
	}
	message := command()
	if batch, ok := message.(tea.BatchMsg); ok {
		for _, nested := range batch {
			model = runCommand(t, model, nested)
		}
		return model
	}
	return updateModel(t, model, message)
}

func TestHomeNavigationGroupsActionsIntoSubmenus(t *testing.T) {
	tests := []struct {
		name         string
		homeIndex    int
		sectionIndex int
		want         screen
	}{
		{name: "protect", homeIndex: 0, sectionIndex: 0, want: screenProtect},
		{name: "restore", homeIndex: 0, sectionIndex: 1, want: screenRestore},
		{name: "inspect", homeIndex: 1, sectionIndex: 0, want: screenInspect},
		{name: "verify", homeIndex: 1, sectionIndex: 1, want: screenVerify},
		{name: "browse", homeIndex: 1, sectionIndex: 2, want: screenList},
		{name: "hash", homeIndex: 2, sectionIndex: 0, want: screenHash},
		{name: "benchmark", homeIndex: 2, sectionIndex: 1, want: screenBenchmark},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := NewModel(&fakeService{})
			for range test.homeIndex {
				model = updateModel(t, model, key("down"))
			}
			model = updateModel(t, model, key("enter"))
			if model.screen != screenSection {
				t.Fatalf("home item %d reached screen %d, want section menu", test.homeIndex, model.screen)
			}
			for range test.sectionIndex {
				model = updateModel(t, model, key("down"))
			}
			model = updateModel(t, model, key("enter"))
			if model.screen != test.want {
				t.Fatalf("submenu item %d reached screen %d, want %d", test.sectionIndex, model.screen, test.want)
			}
		})
	}

	model := NewModel(&fakeService{})
	for range 3 {
		model = updateModel(t, model, key("down"))
	}
	model = updateModel(t, model, key("enter"))
	if model.screen != screenHelp {
		t.Fatalf("help item reached screen %d", model.screen)
	}
}

func TestHomeViewPresentsLogicalWorkspaces(t *testing.T) {
	model := NewModel(&fakeService{})
	view := model.View()
	for _, label := range []string{"Secure files", "Inspect & validate", "Tools & reports", "Help & about"} {
		if !strings.Contains(view, label) {
			t.Fatalf("home view missing workspace %q:\n%s", label, view)
		}
	}
	if strings.Contains(view, "Protect files") {
		t.Fatalf("home view leaked a nested action:\n%s", view)
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

func TestPickerFuzzyFindsAndSelectsFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "release-notes.txt")
	if err := os.WriteFile(target, []byte("notes"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "receipt.txt"), []byte("other"), 0o600); err != nil {
		t.Fatalf("write distractor: %v", err)
	}

	model := NewModel(&fakeService{})
	model.protect.inputPath = target
	model.screen = screenProtect
	updated, command := model.Update(key("enter"))
	model = updated.(Model)
	model = runCommand(t, model, command)
	if model.picker == nil || !model.picker.ready {
		t.Fatal("source picker did not become ready")
	}

	model = updateModel(t, model, key("/"))
	if !model.picker.filtering || !model.picker.query.Focused() {
		t.Fatal("slash did not focus fuzzy find")
	}
	updated, command = model.Update(key("release"))
	model = updated.(Model)
	model = runCommand(t, model, command)
	if len(model.picker.matches) != 1 || model.picker.matches[0].name != "release-notes.txt" {
		t.Fatalf("fzf matches = %#v", model.picker.matches)
	}
	if view := model.View(); !strings.Contains(view, "FUZZY FIND") || !strings.Contains(view, "release-notes.txt") {
		t.Fatalf("fuzzy picker view missing query results:\n%s", view)
	}

	model = updateModel(t, model, key("enter"))
	if model.screen != screenProtect || model.protect.inputPath != target {
		t.Fatalf("fuzzy selection path=%q screen=%d", model.protect.inputPath, model.screen)
	}
}

func TestPickerFuzzyEscapeClearsBeforeClosing(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "release-notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	model := NewModel(&fakeService{})
	model.protect.inputPath = filepath.Join(root, "release-notes.txt")
	model.screen = screenProtect
	updated, command := model.Update(key("enter"))
	model = updated.(Model)
	model = runCommand(t, model, command)
	model = updateModel(t, model, key("/"))
	updated, command = model.Update(key("release"))
	model = updated.(Model)
	model = runCommand(t, model, command)

	model = updateModel(t, model, key("esc"))
	if !model.picker.filtering || model.picker.query.Value() != "" {
		t.Fatal("first escape did not clear the fuzzy query")
	}
	model = updateModel(t, model, key("esc"))
	if model.picker == nil || model.picker.filtering {
		t.Fatal("second escape did not leave fuzzy mode")
	}
	model = updateModel(t, model, key("esc"))
	if model.screen != screenProtect || model.picker != nil {
		t.Fatal("third escape did not close picker")
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

func TestCompletionReleasesOperationCancel(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenRunning
	model.operationID = 13
	cancelCount := 0
	model.cancel = func() { cancelCount++ }
	model = updateModel(t, model, operationDoneMsg{operationID: 13, kind: operationProtect, value: app.ProtectResult{OutputPath: "done.cys"}})
	if cancelCount != 1 || model.cancel != nil || model.cancelRequested {
		t.Fatalf("completion cancel state: count=%d cancel=%v requested=%t", cancelCount, model.cancel, model.cancelRequested)
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

func TestProgressBarRendersKnownAndUnknownProgress(t *testing.T) {
	tests := []struct {
		name    string
		current int64
		total   int64
		width   int
		want    int
	}{
		{name: "quarter", current: 1, total: 4, width: 32, want: 8},
		{name: "complete", current: 9, total: 9, width: 32, want: 32},
		{name: "clamped", current: 10, total: 9, width: 32, want: 32},
		{name: "unknown", current: 1, total: 0, width: 32, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := progressFillWidth(test.current, test.total, test.width); got != test.want {
				t.Fatalf("progressFillWidth(%d, %d, %d) = %d, want %d", test.current, test.total, test.width, got, test.want)
			}
		})
	}

	style := defaultStyles()
	known := renderProgress(app.Event{Current: 1, Total: 4}, style)
	if !strings.Contains(known, "25%") || !strings.Contains(known, "1 / 4") {
		t.Fatalf("determinate progress missing percentage or totals: %q", known)
	}
	unknown := renderProgress(app.Event{Phase: app.PhaseEncrypting}, style)
	if !strings.Contains(unknown, "progress is not measurable") {
		t.Fatalf("indeterminate progress missing explanation: %q", unknown)
	}
}

func TestRunningViewDisplaysProgressBar(t *testing.T) {
	model := NewModel(&fakeService{})
	model.screen = screenRunning
	model.progress = app.Event{Phase: app.PhaseBenchmarking, Current: 1, Total: 2}
	view := model.View()
	for _, value := range []string{"BENCHMARKING", "50%", "1 / 2"} {
		if !strings.Contains(view, value) {
			t.Fatalf("running view missing %q:\n%s", value, view)
		}
	}
}
