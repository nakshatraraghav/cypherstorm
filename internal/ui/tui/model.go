package tui

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/credential/keymanage"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/security/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/security/wipe"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
)

type screen uint8

const (
	screenHome screen = iota
	screenSection
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

	homeIndex    int
	section      menuSection
	sectionIndex int
	protect      operationForm
	restore      operationForm
	hash         operationForm
	benchmark    operationForm
	inspect      operationForm
	verify       operationForm
	list         operationForm
	picker       *pickerState
	dropdown     *dropdownState
	baseContext  context.Context

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
	if next, command, handled := m.handleOperationMessage(message); handled {
		return next, command
	}
	if next, command, handled := m.handleGlobalInput(message); handled {
		return next, command
	}
	return m.updateScreen(message)
}

func (m Model) handleOperationMessage(message tea.Msg) (Model, tea.Cmd, bool) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		if m.picker != nil {
			m.picker.model.SetHeight(max(5, m.height-12))
		}
		return m, nil, true
	case progressMsg:
		if m.screen != screenRunning || message.operationID != m.operationID {
			return m, nil, true
		}
		m.progress = message.event
		return m, waitProgress(message.operationID, message.events), true
	case progressClosedMsg:
		return m, nil, true
	case operationDoneMsg:
		if message.operationID != m.operationID {
			return m, nil, true
		}
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.cancelRequested = false
		if message.err != nil {
			if message.kind == operationBenchmark {
				if _, ok := message.value.(report.Report); ok {
					m.setResult(message)
					m.resultTitle = "Benchmark completed with errors"
					m.resultLines = append([]string{message.err.Error()}, m.resultLines...)
					m.screen = screenResult
					return m, nil, true
				}
			}
			m.lastError = message.err
			m.screen = screenError
			return m, nil, true
		}
		m.setResult(message)
		m.screen = screenResult
		return m, nil, true
	default:
		return m, nil, false
	}
}

func (m Model) handleGlobalInput(message tea.Msg) (Model, tea.Cmd, bool) {
	key, isKey := message.(tea.KeyMsg)
	if isKey && m.screen == screenRunning && key.String() == "q" {
		m.requestCancel()
		return m, nil, true
	}
	if isKey && key.String() == "ctrl+c" {
		if m.screen == screenRunning {
			m.requestCancel()
			return m, nil, true
		}
		m.clearSecrets()
		return m, tea.Quit, true
	}
	if m.screen == screenPicker {
		next, command := m.updatePicker(message)
		return next.(Model), command, true
	}
	if m.screen == screenDropdown {
		next, command := m.updateDropdown(message)
		return next.(Model), command, true
	}
	if !isKey || key.String() != "esc" {
		return m, nil, false
	}
	switch m.screen {
	case screenRunning:
		m.requestCancel()
	case screenHome:
		m.clearSecrets()
		return m, tea.Quit, true
	case screenConfirm:
		m.screen = screenForOperation(m.pendingKind)
		m.discardPending()
	default:
		m.clearSecrets()
		m.screen = screenHome
		m.validation = ""
	}
	return m, nil, true
}

func (m Model) updateScreen(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	switch m.screen {
	case screenHome:
		return m.updateHome(message)
	case screenSection:
		return m.updateSection(message)
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
	items := homeMenu()
	switch key.String() {
	case "up", "k":
		m.homeIndex = cycle(m.homeIndex, -1, len(items))
	case "down", "j", "tab":
		m.homeIndex = cycle(m.homeIndex, 1, len(items))
	case "enter":
		m.validation = ""
		selected := items[m.homeIndex]
		if selected.target == screenSection {
			m.section = sectionForHomeIndex(m.homeIndex)
			m.sectionIndex = 0
		}
		m.screen = selected.target
	}
	return m, nil
}

func (m Model) updateSection(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	items := sectionInfo(m.section).items
	switch key.String() {
	case "up", "k":
		m.sectionIndex = cycle(m.sectionIndex, -1, len(items))
	case "down", "j", "tab":
		m.sectionIndex = cycle(m.sectionIndex, 1, len(items))
	case "enter":
		m.validation = ""
		m.screen = items[m.sectionIndex].target
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
	key, err := keymanage.Load(keyPath)
	if err != nil {
		return app.Credential{}, fmt.Errorf("read key file: %w", err)
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
	wipe.Bytes(value)
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
	case screenSection:
		body = m.sectionView()
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
		body = m.runningView()
	case screenResult:
		body = m.resultView()
	case screenError:
		body = m.errorView()
	}
	return m.shell(body)
}

func (m Model) homeView() string {
	items := homeMenu()
	lines := []string{
		m.styles.hero.Render("CypherStorm"),
		m.styles.muted.Render("Nothing personal leaves the room."),
		"",
	}
	for index, item := range items {
		lines = append(lines, m.menuCard(item, index == m.homeIndex, 58))
	}
	return strings.Join(lines, "\n")
}

func (m Model) sectionView() string {
	section := sectionInfo(m.section)
	lines := []string{
		m.styles.eyebrow.Render(section.tag),
		m.styles.hero.Render(section.title),
		m.styles.muted.Render(section.description),
		"",
	}
	for index, item := range section.items {
		lines = append(lines, m.menuCard(item, index == m.sectionIndex, 58))
	}
	lines = append(lines, "", m.styles.help.Render("↑/↓ choose  •  Enter open  •  Esc home"))
	return strings.Join(lines, "\n")
}

func (m Model) menuCard(item menuItem, selected bool, maxWidth int) string {
	width := maxWidth
	if m.width > 0 {
		width = min(maxWidth, max(36, m.width-12))
	}
	tag := m.styles.tag.Render(item.tag)
	content := m.styles.cardTitle.Render(item.title) + "  " + tag + "\n" + m.styles.cardDescription.Render(item.description)
	if selected {
		return m.styles.selectedCard.Width(width).Render("› " + content)
	}
	return m.styles.card.Width(width).Render("  " + content)
}

func (m Model) formView(form operationForm) string {
	view := form.view(m.styles, max(50, m.width))
	if m.validation != "" {
		view += "\n\n" + m.styles.error.Render(m.validation)
	}
	return view
}

func (m Model) runningView() string {
	status := m.styles.label.Render("PHASE  ") + m.styles.accent.Render(strings.ToUpper(string(m.progress.Phase)))
	if m.progress.Detail != "" {
		status += "\n" + m.progress.Detail
	}
	if m.cancelRequested {
		status += "\n\n" + m.styles.warning.Render("Cancellation requested. Waiting for secure cleanup.")
	}
	return strings.Join([]string{
		m.styles.eyebrow.Render("OPERATION IN PROGRESS"),
		m.styles.hero.Render("Working safely"),
		m.styles.muted.Render("The destination is not published until the operation completes."),
		"",
		status,
		"",
		renderProgress(m.progress, m.styles),
		"",
		m.styles.help.Render("Esc, Ctrl+C, or Q requests safe cancellation"),
	}, "\n")
}

func (m Model) errorView() string {
	return strings.Join([]string{
		m.styles.eyebrow.Render("OPERATION STOPPED"),
		m.styles.error.Render("No output was published"),
		"",
		fmt.Sprint(m.lastError),
		"",
		m.styles.help.Render("Enter returns to the form  •  Esc returns home"),
	}, "\n")
}

func (m Model) confirmView() string {
	var summary string
	switch request := m.pending.(type) {
	case app.ProtectRequest:
		summary = fmt.Sprintf("Input        %s\nOutput       %s\nCompression  %s\nEncryption   %s\nOverwrite    %t", request.InputPath, request.OutputPath, request.Codec, request.Cipher, request.Overwrite)
	case app.RestoreRequest:
		summary = fmt.Sprintf("Archive      %s\nDestination  %s", request.InputPath, request.OutputPath)
	case app.HashRequest:
		summary = fmt.Sprintf("Input      %s\nAlgorithm  %s", request.InputPath, request.Algorithm)
	case app.BenchmarkRequest:
		summary = fmt.Sprintf("Input   %s\nReport  %s", request.InputPath, request.OutputPath)
	case app.InspectRequest:
		summary = fmt.Sprintf("Archive  %s\n\nHeader fields are visible before authentication.", request.InputPath)
	case app.VerifyRequest:
		summary = fmt.Sprintf("Archive  %s\nMode     %s", request.InputPath, request.Mode)
	case app.ListRequest:
		summary = fmt.Sprintf("Archive  %s", request.InputPath)
	}
	return strings.Join([]string{
		m.styles.eyebrow.Render("FINAL CHECK"),
		m.styles.hero.Render("Review operation"),
		m.styles.muted.Render("Confirm only after the paths and settings are correct."),
		"",
		m.styles.eyebrow.Render("SUMMARY"),
		summary,
		"",
		m.styles.primaryButton.Render("Run operation"),
		m.styles.help.Render("Enter runs  •  Esc returns to the form"),
	}, "\n")
}

func (m Model) resultView() string {
	available := m.height - 14
	if available < 1 || available > len(m.resultLines) {
		available = len(m.resultLines)
	}
	end := min(len(m.resultLines), m.resultOffset+available)
	lines := m.resultLines[m.resultOffset:end]
	content := strings.Join(lines, "\n")
	if content == "" {
		content = m.styles.muted.Render("No details returned.")
	}
	return strings.Join([]string{
		m.styles.eyebrow.Render("COMPLETE"),
		m.styles.success.Render(m.resultTitle),
		"",
		content,
		"",
		m.styles.help.Render("↑/↓ scroll results  •  Enter or Esc returns home"),
	}, "\n")
}

func (m Model) helpView() string {
	return strings.Join([]string{
		m.styles.eyebrow.Render("WORKSPACE GUIDE"),
		m.styles.hero.Render("Private by design"),
		m.styles.muted.Render("CypherStorm protects files with a canonical authenticated container."),
		"",
		m.styles.eyebrow.Render("NAVIGATION"),
		"↑/↓ or Tab moves focus\nEnter opens or confirms\nEsc returns to the previous workspace\nCtrl+C exits safely",
		"",
		m.styles.eyebrow.Render("SECURITY"),
		"Passwords and raw-key bytes are never rendered.\nRestore reads cipher and compression choices from authenticated metadata.\nInspect displays unauthenticated public header fields only.",
		"",
		m.styles.help.Render("Enter or Esc returns home"),
	}, "\n")
}
