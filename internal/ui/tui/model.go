package tui

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
)

type screen uint8

const (
	screenHome screen = iota
	screenProtect
	screenRestore
	screenHash
	screenBenchmark
	screenInspect
	screenVerify
	screenList
	screenHelp
	screenPicker
	screenDropdown
	screenConfirm
	screenRunning
	screenResult
	screenError
)

type operationKind uint8

const (
	operationProtect operationKind = iota
	operationRestore
	operationHash
	operationBenchmark
	operationInspect
	operationVerify
	operationList
)

type Model struct {
	service Service
	screen  screen
	styles  styles
	width   int
	height  int

	homeIndex   int
	protect     operationForm
	restore     operationForm
	hash        operationForm
	benchmark   operationForm
	inspect     operationForm
	verify      operationForm
	list        operationForm
	picker      *pickerState
	dropdown    *dropdownState
	baseContext context.Context

	pendingKind operationKind
	pending     any
	validation  string

	operationID     uint64
	cancel          context.CancelFunc
	cancelRequested bool
	progress        app.Event

	resultTitle  string
	resultLines  []string
	resultOffset int
	lastError    error
}

func NewModel(service Service) Model {
	return NewModelWithContext(context.Background(), service)
}

func NewModelWithContext(ctx context.Context, service Service) Model {
	return Model{
		service:     service,
		baseContext: ctx,
		screen:      screenHome,
		styles:      defaultStyles(),
		protect:     newOperationForm(formProtect),
		restore:     newOperationForm(formRestore),
		hash:        newOperationForm(formHash),
		benchmark:   newOperationForm(formBenchmark),
		inspect:     newOperationForm(formInspect),
		verify:      newOperationForm(formVerify),
		list:        newOperationForm(formList),
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) String() string {
	return fmt.Sprintf("TUI{screen:%d operation:%d cancelling:%t}", m.screen, m.operationID, m.cancelRequested)
}

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		if m.picker != nil {
			m.picker.model.SetHeight(max(5, m.height-12))
		}
		return m, nil
	case progressMsg:
		if m.screen != screenRunning || message.operationID != m.operationID {
			return m, nil
		}
		m.progress = message.event
		return m, waitProgress(message.operationID, message.events)
	case progressClosedMsg:
		return m, nil
	case operationDoneMsg:
		if message.operationID != m.operationID {
			return m, nil
		}
		m.cancel = nil
		m.cancelRequested = false
		if message.err != nil {
			if message.kind == operationBenchmark {
				if _, ok := message.value.(report.Report); ok {
					m.setResult(message)
					m.resultTitle = "Benchmark completed with errors"
					m.resultLines = append([]string{message.err.Error()}, m.resultLines...)
					m.screen = screenResult
					return m, nil
				}
			}
			m.lastError = message.err
			m.screen = screenError
			return m, nil
		}
		m.setResult(message)
		m.screen = screenResult
		return m, nil
	}

	key, isKey := message.(tea.KeyMsg)
	if isKey && m.screen == screenRunning && key.String() == "q" {
		m.requestCancel()
		return m, nil
	}
	if isKey && key.String() == "ctrl+c" {
		if m.screen == screenRunning {
			m.requestCancel()
			return m, nil
		}
		m.clearSecrets()
		return m, tea.Quit
	}
	if m.screen == screenPicker {
		return m.updatePicker(message)
	}
	if m.screen == screenDropdown {
		return m.updateDropdown(message)
	}
	if isKey && key.String() == "esc" {
		switch m.screen {
		case screenRunning:
			m.requestCancel()
			return m, nil
		case screenHome:
			m.clearSecrets()
			return m, tea.Quit
		case screenConfirm:
			m.screen = screenForOperation(m.pendingKind)
			m.discardPending()
			return m, nil
		default:
			m.clearSecrets()
			m.screen = screenHome
			m.validation = ""
			return m, nil
		}
	}

	switch m.screen {
	case screenHome:
		return m.updateHome(message)
	case screenProtect:
		command, action := m.protect.update(message)
		return m.handleFormAction(formProtect, action, command)
	case screenRestore:
		command, action := m.restore.update(message)
		return m.handleFormAction(formRestore, action, command)
	case screenHash:
		command, action := m.hash.update(message)
		return m.handleFormAction(formHash, action, command)
	case screenBenchmark:
		command, action := m.benchmark.update(message)
		return m.handleFormAction(formBenchmark, action, command)
	case screenInspect:
		command, action := m.inspect.update(message)
		return m.handleFormAction(formInspect, action, command)
	case screenVerify:
		command, action := m.verify.update(message)
		return m.handleFormAction(formVerify, action, command)
	case screenList:
		command, action := m.list.update(message)
		return m.handleFormAction(formList, action, command)
	case screenConfirm:
		if isKey && key.String() == "enter" {
			return m.startOperation()
		}
	case screenResult:
		if isKey {
			switch key.String() {
			case "up", "k":
				if m.resultOffset > 0 {
					m.resultOffset--
				}
			case "down", "j":
				if m.resultOffset+1 < len(m.resultLines) {
					m.resultOffset++
				}
			case "enter":
				m.screen = screenHome
			}
		}
	case screenError:
		if isKey && key.String() == "enter" {
			m.screen = screenForOperation(m.pendingKind)
		}
	case screenHelp:
		if isKey && key.String() == "enter" {
			m.screen = screenHome
		}
	}
	return m, nil
}

func (m Model) updateHome(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	const menuCount = 8
	switch key.String() {
	case "up", "k":
		m.homeIndex = cycle(m.homeIndex, -1, menuCount)
	case "down", "j", "tab":
		m.homeIndex = cycle(m.homeIndex, 1, menuCount)
	case "enter":
		m.validation = ""
		switch m.homeIndex {
		case 0:
			m.screen = screenProtect
		case 1:
			m.screen = screenRestore
		case 2:
			m.screen = screenInspect
		case 3:
			m.screen = screenVerify
		case 4:
			m.screen = screenList
		case 5:
			m.screen = screenHash
		case 6:
			m.screen = screenBenchmark
		case 7:
			m.screen = screenHelp
		}
	}
	return m, nil
}

func (m *Model) prepareProtect() {
	form := &m.protect
	outputPath := form.outputPreview()
	if err := validatePaths(form.inputPath, outputPath, form.overwrite); err != nil {
		m.validation = err.Error()
		return
	}
	credential, err := formCredential(form, true)
	if err != nil {
		m.validation = err.Error()
		return
	}
	m.pendingKind = operationProtect
	m.pending = app.ProtectRequest{
		InputPath: form.inputPath, OutputPath: outputPath, Credential: credential,
		Codec: compress.AllCodecs()[form.codecIndex].ID(), Cipher: crypto.AllCipherIDs()[form.cipherIndex], Overwrite: form.overwrite,
	}
	m.validation = ""
	m.screen = screenConfirm
}

func (m *Model) prepareRestore() {
	form := &m.restore
	outputPath := form.outputPreview()
	if err := validatePaths(form.inputPath, outputPath, false); err != nil {
		m.validation = err.Error()
		return
	}
	credential, err := formCredential(form, false)
	if err != nil {
		m.validation = err.Error()
		return
	}
	m.pendingKind = operationRestore
	m.pending = app.RestoreRequest{InputPath: form.inputPath, OutputPath: outputPath, Credential: credential}
	m.validation = ""
	m.screen = screenConfirm
}

func (m *Model) prepareHash() {
	if m.hash.inputPath == "" {
		m.validation = "source is required"
		return
	}
	if _, err := os.Lstat(m.hash.inputPath); err != nil {
		m.validation = fmt.Sprintf("input path: %v", err)
		return
	}
	m.pendingKind = operationHash
	m.pending = app.HashRequest{InputPath: m.hash.inputPath, Algorithm: hashing.AllIDs()[m.hash.algorithmIdx]}
	m.validation = ""
	m.screen = screenConfirm
}

func (m *Model) prepareBenchmark() {
	outputPath := m.benchmark.outputPreview()
	if err := validatePaths(m.benchmark.inputPath, outputPath, false); err != nil {
		m.validation = err.Error()
		return
	}
	m.pendingKind = operationBenchmark
	m.pending = app.BenchmarkRequest{InputPath: m.benchmark.inputPath, OutputPath: outputPath}
	m.validation = ""
	m.screen = screenConfirm
}
func (m *Model) prepareInspect() {
	if m.inspect.inputPath == "" {
		m.validation = "protected input is required"
		return
	}
	if _, err := os.Lstat(m.inspect.inputPath); err != nil {
		m.validation = fmt.Sprintf("input path: %v", err)
		return
	}
	m.pendingKind = operationInspect
	m.pending = app.InspectRequest{InputPath: m.inspect.inputPath}
	m.validation = ""
	m.screen = screenConfirm
}

func (m *Model) prepareVerify() {
	if m.verify.inputPath == "" {
		m.validation = "protected input is required"
		return
	}
	if _, err := os.Lstat(m.verify.inputPath); err != nil {
		m.validation = fmt.Sprintf("input path: %v", err)
		return
	}
	credential, err := formCredential(&m.verify, false)
	if err != nil {
		m.validation = err.Error()
		return
	}
	m.pendingKind = operationVerify
	m.pending = app.VerifyRequest{InputPath: m.verify.inputPath, Credential: credential, Mode: app.VerifyFull}
	m.validation = ""
	m.screen = screenConfirm
}

func (m *Model) prepareList() {
	if m.list.inputPath == "" {
		m.validation = "protected input is required"
		return
	}
	if _, err := os.Lstat(m.list.inputPath); err != nil {
		m.validation = fmt.Sprintf("input path: %v", err)
		return
	}
	credential, err := formCredential(&m.list, false)
	if err != nil {
		m.validation = err.Error()
		return
	}
	m.pendingKind = operationList
	m.pending = app.ListRequest{InputPath: m.list.inputPath, Credential: credential}
	m.validation = ""
	m.screen = screenConfirm
}

func validatePaths(inputPath, outputPath string, overwrite bool) error {
	if inputPath == "" || outputPath == "" {
		return fmt.Errorf("input and output paths are required")
	}
	if _, err := os.Lstat(inputPath); err != nil {
		return fmt.Errorf("input path: %w", err)
	}
	if err := fsutil.ValidateNoContainment(inputPath, outputPath); err != nil {
		return err
	}
	if err := fsutil.ValidateOutputTarget(outputPath, overwrite); err != nil {
		return err
	}
	return nil
}

func formCredential(form *operationForm, confirm bool) (app.Credential, error) {
	if form.credential == app.CredentialPassword {
		password := form.password.Value()
		if password == "" {
			return app.Credential{}, fmt.Errorf("password is required")
		}
		if confirm && password != form.confirmation.Value() {
			return app.Credential{}, fmt.Errorf("password confirmation does not match")
		}
		return app.Credential{Kind: app.CredentialPassword, Password: []byte(password)}, nil
	}
	keyPath := form.keyFilePath
	if keyPath == "" {
		return app.Credential{}, fmt.Errorf("key-file path is required")
	}
	info, err := os.Lstat(keyPath)
	if err != nil {
		return app.Credential{}, fmt.Errorf("key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return app.Credential{}, fmt.Errorf("key file must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return app.Credential{}, fmt.Errorf("key-file permissions must be 0600 or stricter")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return app.Credential{}, fmt.Errorf("read key file: %w", err)
	}
	if len(key) != kdf.MasterKeySize {
		clearSecret(key)
		return app.Credential{}, fmt.Errorf("key file must contain exactly %d binary bytes", kdf.MasterKeySize)
	}
	return app.Credential{Kind: app.CredentialRawKey, RawKey: key}, nil
}

func (m Model) startOperation() (tea.Model, tea.Cmd) {
	m.operationID++
	operationID := m.operationID
	ctx, cancel := context.WithCancel(m.baseContext)
	m.cancel = cancel
	m.cancelRequested = false
	m.progress = app.Event{Phase: app.PhaseValidating}
	events := make(chan app.Event, 1)
	pending := m.pending
	kind := m.pendingKind
	command := operationCommand(m.service, ctx, operationID, kind, pending, events)
	m.pending = nil
	m.clearSecrets()
	m.screen = screenRunning
	return m, tea.Batch(command, waitProgress(operationID, events))
}

func operationCommand(service Service, ctx context.Context, operationID uint64, kind operationKind, pending any, events chan app.Event) tea.Cmd {
	return func() tea.Msg {
		sink := func(event app.Event) {
			select {
			case events <- event:
			default:
				select {
				case <-events:
				default:
				}
				select {
				case events <- event:
				default:
				}
			}
		}
		message := operationDoneMsg{operationID: operationID, kind: kind}
		switch request := pending.(type) {
		case app.ProtectRequest:
			message.value, message.err = service.Protect(ctx, request, sink)
			clearCredential(&request.Credential)
		case app.RestoreRequest:
			message.value, message.err = service.Restore(ctx, request, sink)
			clearCredential(&request.Credential)
		case app.HashRequest:
			message.value, message.err = service.Hash(ctx, request, sink)
		case app.BenchmarkRequest:
			message.value, message.err = service.Benchmark(ctx, request, sink)
			message.outputPath = request.OutputPath
		case app.InspectRequest:
			message.value, message.err = service.Inspect(ctx, request, sink)
		case app.VerifyRequest:
			message.value, message.err = service.Verify(ctx, request, sink)
			clearCredential(&request.Credential)
		case app.ListRequest:
			message.value, message.err = service.List(ctx, request, sink)
			clearCredential(&request.Credential)
		default:
			message.err = fmt.Errorf("tui: invalid pending operation")
		}
		close(events)
		return message
	}
}

func waitProgress(operationID uint64, events <-chan app.Event) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-events
		if !ok {
			return progressClosedMsg{operationID: operationID}
		}
		return progressMsg{operationID: operationID, event: event, events: events}
	}
}

func (m *Model) requestCancel() {
	if m.cancel != nil && !m.cancelRequested {
		m.cancelRequested = true
		m.cancel()
	}
}

func (m *Model) setResult(message operationDoneMsg) {
	m.resultOffset = 0
	switch value := message.value.(type) {
	case app.ProtectResult:
		m.resultTitle = "Protection complete"
		m.resultLines = []string{value.OutputPath, fmt.Sprintf("Input: %d bytes", value.InputBytes), fmt.Sprintf("Output: %d bytes", value.OutputBytes)}
	case app.RestoreResult:
		m.resultTitle = "Restore complete"
		m.resultLines = []string{value.OutputPath}
	case []app.HashResult:
		m.resultTitle = "Hash results"
		m.resultLines = make([]string, 0, len(value))
		for _, result := range value {
			m.resultLines = append(m.resultLines, fmt.Sprintf("%s  %s", hex.EncodeToString(result.Digest), result.Path))
		}
	case report.Report:
		m.resultTitle = "Benchmark results"
		m.resultLines = []string{fmt.Sprintf("Successes: %d", len(value.Successes)), fmt.Sprintf("Failures: %d", len(value.Failures))}
		if message.outputPath != "" {
			m.resultLines = append(m.resultLines, "Report: "+message.outputPath)
		}
		for _, failure := range value.Failures {
			m.resultLines = append(m.resultLines, fmt.Sprintf("%s + %s: %v", failure.Combination.Codec, failure.Combination.Cipher, failure.Err))
		}
	case app.InspectResult:
		m.resultTitle = "Inspection"
		m.resultLines = []string{fmt.Sprintf("Format: v%d", value.FormatVersion), "Cipher: " + string(value.Cipher), "Compression: " + string(value.Codec), fmt.Sprintf("Record size: %d", value.RecordSize), "Header is unauthenticated"}
	case app.VerifyResult:
		m.resultTitle = "Verification complete"
		m.resultLines = []string{fmt.Sprintf("Authenticated: %t", value.Authenticated), fmt.Sprintf("Archive valid: %t", value.ArchiveValidated), fmt.Sprintf("Entries: %d", value.Summary.Entries)}
	case app.ListResult:
		m.resultTitle = "Archive contents"
		m.resultLines = make([]string, 0, len(value.Entries)+1)
		for _, entry := range value.Entries {
			m.resultLines = append(m.resultLines, fmt.Sprintf("%-9s %10d %s", entry.Type, entry.Size, entry.Path))
		}
		m.resultLines = append(m.resultLines, fmt.Sprintf("%d entries, %d bytes", value.Summary.Entries, value.Summary.Bytes))
	default:
		m.resultTitle = "Operation complete"
		m.resultLines = nil
	}
}

func (m *Model) clearSecrets() {
	m.protect.clearSecrets()
	m.restore.clearSecrets()
	m.inspect.clearSecrets()
	m.verify.clearSecrets()
	m.list.clearSecrets()
	m.discardPending()
}

func (m *Model) discardPending() {
	if request, ok := m.pending.(app.ProtectRequest); ok {
		clearCredential(&request.Credential)
	}
	if request, ok := m.pending.(app.RestoreRequest); ok {
		clearCredential(&request.Credential)
	}
	if request, ok := m.pending.(app.VerifyRequest); ok {
		clearCredential(&request.Credential)
	}
	if request, ok := m.pending.(app.ListRequest); ok {
		clearCredential(&request.Credential)
	}
	m.pending = nil
}

func clearCredential(credential *app.Credential) {
	clearSecret(credential.Password)
	clearSecret(credential.RawKey)
}

func clearSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func screenForOperation(kind operationKind) screen {
	switch kind {
	case operationProtect:
		return screenProtect
	case operationRestore:
		return screenRestore
	case operationHash:
		return screenHash
	case operationBenchmark:
		return screenBenchmark
	case operationInspect:
		return screenInspect
	case operationVerify:
		return screenVerify
	case operationList:
		return screenList
	default:
		return screenHome

	}
}

type progressMsg struct {
	operationID uint64
	event       app.Event
	events      <-chan app.Event
}

type progressClosedMsg struct{ operationID uint64 }

type operationDoneMsg struct {
	operationID uint64
	kind        operationKind
	value       any
	err         error
	outputPath  string
}

func (m Model) handleFormAction(kind formKind, action formAction, command tea.Cmd) (tea.Model, tea.Cmd) {
	switch action.kind {
	case formActionBrowse:
		return m, m.openPicker(kind, action.slot)
	case formActionDropdown:
		m.openDropdown(kind, action.slot)
		return m, nil
	case formActionSubmit:
		switch kind {
		case formProtect:
			m.prepareProtect()
		case formRestore:
			m.prepareRestore()
		case formHash:
			m.prepareHash()
		case formBenchmark:
			m.prepareBenchmark()
		case formInspect:
			m.prepareInspect()
		case formVerify:
			m.prepareVerify()
		case formList:
			m.prepareList()
		}
	}
	return m, command
}

func (m Model) View() string {
	if m.width > 0 && (m.width < 50 || m.height < 12) {
		return "CypherStorm\n\nTerminal is too small. Resize to at least 50x12.\n\nCtrl+C: quit"
	}
	if m.screen == screenPicker {
		return m.pickerView()
	}
	if m.screen == screenDropdown {
		return m.dropdownView()
	}
	var body string
	switch m.screen {
	case screenHome:
		body = m.homeView()
	case screenProtect:
		body = m.formView(m.protect)
	case screenRestore:
		body = m.formView(m.restore)
	case screenHash:
		body = m.formView(m.hash)
	case screenBenchmark:
		body = m.formView(m.benchmark)
	case screenHelp:
		body = m.helpView()
	case screenInspect:
		body = m.formView(m.inspect)
	case screenVerify:
		body = m.formView(m.verify)
	case screenList:
		body = m.formView(m.list)
	case screenConfirm:
		body = m.confirmView()
	case screenRunning:
		status := fmt.Sprintf("Phase: %s", m.progress.Phase)
		if m.progress.Detail != "" {
			status += "\n" + m.progress.Detail
		}
		if m.cancelRequested {
			status += "\nCancellation requested; waiting for cleanup."
		}
		body = m.styles.title.Render("Working") + "\n\n" + status + "\n\n" + m.styles.help.Render("Esc/Ctrl+C/Q: cancel safely")
	case screenResult:
		body = m.resultView()
	case screenError:
		body = m.styles.error.Render("Operation failed") + "\n\n" + fmt.Sprint(m.lastError) + "\n\n" + m.styles.help.Render("Enter: return to form  Esc: home")
	}
	return m.styles.panel.Render(body)
}

func (m Model) homeView() string {
	items := []string{"Protect", "Restore", "Inspect", "Verify", "Browse archive", "Hash", "Benchmark", "Help / About"}
	lines := []string{
		m.styles.brand.Render("CYPHERSTORM"),
		m.styles.muted.Render("Private files, protected locally"),
		"",
	}
	for index, item := range items {
		prefix := "  "
		value := item
		if index == m.homeIndex {
			prefix = m.styles.accent.Render("› ")
			value = m.styles.selectBox.Render(item)
		}
		lines = append(lines, prefix+value)
	}
	lines = append(lines, "", m.styles.help.Render("up/down move  •  enter opens  •  esc quits"))
	return strings.Join(lines, "\n")
}

func (m Model) formView(form operationForm) string {
	view := form.view(m.styles, max(50, m.width))
	if m.validation != "" {
		view += "\n\n" + m.styles.error.Render(m.validation)
	}
	return view
}

func (m Model) confirmView() string {
	var summary string
	switch request := m.pending.(type) {
	case app.ProtectRequest:
		summary = fmt.Sprintf("Protect\nInput: %s\nOutput: %s\nCompression: %s\nCipher: %s\nOverwrite: %t", request.InputPath, request.OutputPath, request.Codec, request.Cipher, request.Overwrite)
	case app.RestoreRequest:
		summary = fmt.Sprintf("Restore\nInput: %s\nDestination: %s", request.InputPath, request.OutputPath)
	case app.HashRequest:
		summary = fmt.Sprintf("Hash\nInput: %s\nAlgorithm: %s", request.InputPath, request.Algorithm)
	case app.BenchmarkRequest:
		summary = fmt.Sprintf("Benchmark\nInput: %s\nReport: %s", request.InputPath, request.OutputPath)
	case app.InspectRequest:
		summary = fmt.Sprintf("Inspect\nInput: %s\nHeader fields are unauthenticated", request.InputPath)
	case app.VerifyRequest:
		summary = fmt.Sprintf("Verify\nInput: %s\nMode: %s", request.InputPath, request.Mode)
	case app.ListRequest:
		summary = fmt.Sprintf("Browse archive\nInput: %s", request.InputPath)
	}
	return m.styles.title.Render("Confirm") + "\n\n" + summary + "\n\n" + m.styles.help.Render("Enter: run  Esc: edit")
}

func (m Model) resultView() string {
	available := m.height - 9
	if available < 1 || available > len(m.resultLines) {
		available = len(m.resultLines)
	}
	end := min(len(m.resultLines), m.resultOffset+available)
	lines := m.resultLines[m.resultOffset:end]
	return m.styles.success.Render(m.resultTitle) + "\n\n" + strings.Join(lines, "\n") + "\n\n" + m.styles.help.Render("Up/Down: scroll  Enter/Esc: home")
}

func (m Model) helpView() string {
	return m.styles.title.Render("Help / About") + "\n\nCypherStorm protects files with an authenticated v1 format.\nPasswords and raw-key bytes are never rendered.\nRestore selects cipher and compression from authenticated metadata.\n\n" + m.styles.help.Render("Enter/Esc: home  Ctrl+C: quit")
}
