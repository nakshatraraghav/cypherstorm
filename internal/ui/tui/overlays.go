package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/security/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
)

type pickerState struct {
	model        filepicker.Model
	form         formKind
	slot         slotKind
	returnScreen screen
	title        string
	directories  bool
	ready        bool

	filtering  bool
	query      textinput.Model
	generation uint64
	searching  bool
	matches    []fuzzyMatch
	matchIndex int
}

type dropdownState struct {
	form         formKind
	slot         slotKind
	returnScreen screen
	title        string
	options      []string
	selected     int
}

func (m *Model) openPicker(kind formKind, slot slotKind) tea.Cmd {
	form := m.formForKind(kind)
	picker := filepicker.New()
	picker.ShowHidden = true
	picker.ShowPermissions = false
	picker.ShowSize = true
	picker.AutoHeight = false
	picker.SetHeight(max(5, m.height-12))

	var current, title string
	switch slot {
	case slotInput:
		current = form.inputPath
		title = "Choose a source"
		picker.FileAllowed = true
		picker.DirAllowed = true
		if kind == formRestore || kind == formInspect || kind == formVerify || kind == formList {
			picker.DirAllowed = false
			picker.AllowedTypes = []string{".cys"}
		}
	case slotOutput:
		current = form.outputDir
		title = "Choose a destination folder"
		picker.FileAllowed = false
		picker.DirAllowed = true
	case slotKeyFile:
		current = form.keyFilePath
		title = "Choose a 32-byte raw key"
		picker.FileAllowed = true
		picker.DirAllowed = false
	}
	picker.CurrentDirectory = pickerStartDirectory(current)
	applyPickerStyles(&picker, m.styles)
	query := newFuzzyInput(m.styles)
	m.picker = &pickerState{
		model:        picker,
		form:         kind,
		slot:         slot,
		returnScreen: screenForForm(kind),
		title:        title,
		directories:  picker.DirAllowed,
		// Choosing the current destination does not depend on the asynchronous
		// listing; keep file-source pickers gated until their entries arrive.
		ready: picker.DirAllowed,
		query: query,
	}
	m.validation = ""
	m.screen = screenPicker
	return picker.Init()
}

func pickerStartDirectory(selected string) string {
	if selected != "" {
		if info, err := os.Stat(selected); err == nil {
			if info.IsDir() {
				return selected
			}
			return filepath.Dir(selected)
		}
	}
	current, err := os.Getwd()
	if err != nil {
		return "."
	}
	return current
}

func applyPickerStyles(picker *filepicker.Model, style styles) {
	picker.Cursor = "›"
	picker.Styles.Cursor = style.accent
	picker.Styles.Selected = style.accent
	picker.Styles.Directory = style.accent
	picker.Styles.File = style.path
	picker.Styles.Symlink = style.muted
	picker.Styles.Permission = style.muted
	picker.Styles.FileSize = style.muted
	picker.Styles.EmptyDirectory = style.muted
	picker.Styles.DisabledFile = style.muted
	picker.Styles.DisabledCursor = style.muted
	picker.Styles.DisabledSelected = style.muted
}

func newFuzzyInput(style styles) textinput.Model {
	input := textinput.New()
	input.Prompt = "Find  "
	input.Placeholder = "type to fuzzy-filter"
	input.CharLimit = 128
	input.Width = 42
	input.PromptStyle = style.accent
	input.TextStyle = style.path
	input.PlaceholderStyle = style.muted
	return input
}

func (m Model) updatePicker(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.picker == nil {
		m.screen = screenHome
		return m, nil
	}
	if matches, ok := message.(fuzzyMatchesMsg); ok {
		return m.applyFuzzyMatches(matches)
	}
	if key, ok := message.(tea.KeyMsg); ok {
		if m.picker.filtering {
			return m.updateFuzzyPicker(message)
		}
		if m.picker.ready && strings.HasPrefix(key.String(), "/") {
			m.picker.filtering = true
			m.picker.query.SetValue(strings.TrimPrefix(key.String(), "/"))
			m.picker.matches = nil
			m.picker.matchIndex = 0
			m.picker.searching = false
			focus := m.picker.query.Focus()
			search := m.refreshFuzzyMatches()
			if search == nil {
				return m, focus
			}
			return m, tea.Batch(focus, search)
		}
		if key.String() == "esc" {
			m.screen = m.picker.returnScreen
			m.picker = nil
			return m, nil
		}
		if !m.picker.ready {
			return m, nil
		}
		if key.String() == "s" && m.picker.directories {
			selected := m.picker.model.CurrentDirectory
			m.formForKind(m.picker.form).setPath(m.picker.slot, selected)
			m.screen = m.picker.returnScreen
			m.picker = nil
			return m, nil
		}
	} else {
		m.picker.ready = true
	}

	previousDirectory := m.picker.model.CurrentDirectory
	picker, command := m.picker.model.Update(message)
	m.picker.model = picker
	if picker.CurrentDirectory != previousDirectory {
		m.picker.ready = false
	}
	return m.commitPickerUpdate(message, command)
}

func (m Model) updateFuzzyPicker(message tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := message.(tea.KeyMsg)
	if isKey {
		switch key.String() {
		case "esc":
			if m.picker.query.Value() != "" {
				m.picker.query.SetValue("")
				m.picker.matches = nil
				m.picker.matchIndex = 0
				m.picker.searching = false
				m.picker.generation++
				return m, nil
			}
			m.picker.filtering = false
			m.picker.query.Blur()
			m.picker.matches = nil
			m.picker.matchIndex = 0
			return m, nil
		case "up", "ctrl+p":
			if len(m.picker.matches) > 0 {
				m.picker.matchIndex = cycle(m.picker.matchIndex, -1, len(m.picker.matches))
			}
			return m, nil
		case "down", "ctrl+n":
			if len(m.picker.matches) > 0 {
				m.picker.matchIndex = cycle(m.picker.matchIndex, 1, len(m.picker.matches))
			}
			return m, nil
		case "enter":
			if m.picker.searching || len(m.picker.matches) == 0 {
				return m, nil
			}
			return m.activateFuzzyMatch(m.picker.matches[m.picker.matchIndex])
		}
	}
	before := m.picker.query.Value()
	query, command := m.picker.query.Update(message)
	m.picker.query = query
	if query.Value() == before {
		return m, command
	}
	search := m.refreshFuzzyMatches()
	if command == nil {
		return m, search
	}
	if search == nil {
		return m, command
	}
	return m, tea.Batch(command, search)
}

func (m Model) refreshFuzzyMatches() tea.Cmd {
	m.picker.generation++
	m.picker.matches = nil
	m.picker.matchIndex = 0
	query := m.picker.query.Value()
	m.picker.searching = strings.TrimSpace(query) != ""
	if !m.picker.searching {
		return nil
	}
	return fuzzySearch(
		m.picker.generation,
		m.picker.model.CurrentDirectory,
		query,
		m.picker.model.ShowHidden,
	)
}

func (m Model) applyFuzzyMatches(message fuzzyMatchesMsg) (tea.Model, tea.Cmd) {
	if m.picker == nil ||
		!m.picker.filtering ||
		message.generation != m.picker.generation ||
		message.directory != m.picker.model.CurrentDirectory ||
		message.query != m.picker.query.Value() {
		return m, nil
	}
	m.picker.searching = false
	if message.err != nil {
		m.validation = fmt.Sprintf("find files: %v", message.err)
		m.picker.matches = nil
		return m, nil
	}
	m.picker.matches = message.matches
	m.picker.matchIndex = 0
	return m, nil
}

func (m Model) activateFuzzyMatch(match fuzzyMatch) (tea.Model, tea.Cmd) {
	m.picker.filtering = false
	m.picker.query.Blur()
	m.picker.matches = nil
	m.picker.matchIndex = 0

	top := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")}
	picker, _ := m.picker.model.Update(top)
	for index := 0; index < match.index; index++ {
		picker, _ = picker.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	previousDirectory := picker.CurrentDirectory
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	picker, command := picker.Update(enter)
	m.picker.model = picker
	if picker.CurrentDirectory != previousDirectory {
		m.picker.ready = false
	}
	return m.commitPickerUpdate(enter, command)
}

func (m Model) commitPickerUpdate(message tea.Msg, command tea.Cmd) (tea.Model, tea.Cmd) {
	picker := m.picker.model
	if selected, path := picker.DidSelectFile(message); selected {
		m.formForKind(m.picker.form).setPath(m.picker.slot, path)
		m.screen = m.picker.returnScreen
		m.picker = nil
		return m, nil
	}
	if disabled, path := picker.DidSelectDisabledFile(message); disabled {
		m.validation = fmt.Sprintf("%s cannot be selected here", path)
	}
	return m, command
}

func (m *Model) openDropdown(kind formKind, slot slotKind) {
	form := m.formForKind(kind)
	var title string
	var options []string
	switch slot {
	case slotCredential:
		title = "Credential"
		options = []string{"Password", "Raw key file"}
	case slotCodec:
		title = "Compression"
		for _, codec := range compress.AllCodecs() {
			options = append(options, string(codec.ID()))
		}
	case slotCipher:
		title = "Encryption"
		for _, cipher := range crypto.AllCipherIDs() {
			options = append(options, string(cipher))
		}
	case slotAlgorithm:
		title = "Hash algorithm"
		for _, algorithm := range hashing.AllIDs() {
			options = append(options, string(algorithm))
		}
	}
	m.dropdown = &dropdownState{
		form:         kind,
		slot:         slot,
		returnScreen: screenForForm(kind),
		title:        title,
		options:      options,
		selected:     form.dropdownIndex(slot),
	}
	m.screen = screenDropdown
}

func (m Model) updateDropdown(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.dropdown == nil {
		m.screen = screenHome
		return m, nil
	}
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "up", "k", "shift+tab":
		m.dropdown.selected = cycle(m.dropdown.selected, -1, len(m.dropdown.options))
	case "down", "j", "tab":
		m.dropdown.selected = cycle(m.dropdown.selected, 1, len(m.dropdown.options))
	case "enter", " ":
		m.formForKind(m.dropdown.form).applyDropdown(m.dropdown.slot, m.dropdown.selected)
		m.screen = m.dropdown.returnScreen
		m.dropdown = nil
	case "esc":
		m.screen = m.dropdown.returnScreen
		m.dropdown = nil
	}
	return m, nil
}

func (m Model) pickerView() string {
	if m.picker == nil {
		return ""
	}
	lines := []string{
		m.styles.eyebrow.Render("FILE PICKER"),
		m.styles.hero.Render(m.picker.title),
	}
	if !m.picker.ready {
		lines = append(lines, "", m.styles.muted.Render("Loading folder…"), "", m.styles.help.Render("Esc cancels"))
		return m.shell(strings.Join(lines, "\n"))
	}
	lines = append(lines,
		m.styles.success.Render("READY"),
		m.styles.label.Render("CURRENT LOCATION"),
		m.styles.path.Render(m.picker.model.CurrentDirectory),
		"",
	)
	if m.picker.filtering {
		lines = append(lines,
			m.styles.label.Render("FUZZY FIND"),
			m.picker.query.View(),
			"",
			m.fuzzyMatchesView(),
			"",
			m.styles.help.Render("↑/↓ result  •  Enter opens/selects  •  Esc clears or closes find"),
		)
	} else {
		lines = append(lines, m.picker.model.View(), "")
		if m.picker.directories {
			lines = append(lines, m.styles.help.Render("/ find  •  Enter selects  •  Right opens  •  S chooses this folder  •  Esc cancels"))
		} else {
			lines = append(lines, m.styles.help.Render("/ find  •  Enter selects  •  Right opens  •  Esc cancels"))
		}
	}
	if m.validation != "" {
		lines = append(lines, "", m.styles.error.Render(m.validation))
	}
	return m.shell(strings.Join(lines, "\n"))
}

func (m Model) fuzzyMatchesView() string {
	if m.picker.query.Value() == "" {
		return m.styles.muted.Render("Type a filename or folder name to filter this directory.")
	}
	if m.picker.searching {
		return m.styles.muted.Render("Finding matches with fzf…")
	}
	if len(m.picker.matches) == 0 {
		return m.styles.muted.Render("No matching entries.")
	}
	limit := min(len(m.picker.matches), max(4, m.height-16))
	lines := make([]string, 0, limit+1)
	for index, match := range m.picker.matches[:limit] {
		name := match.name
		if match.isDir {
			name += "/"
		}
		if index == m.picker.matchIndex {
			lines = append(lines, m.styles.accent.Render("› ")+m.styles.selectBox.Render(name))
			continue
		}
		lines = append(lines, "  "+m.styles.path.Render(name))
	}
	if len(m.picker.matches) > limit {
		lines = append(lines, m.styles.muted.Render(fmt.Sprintf("%d more matches", len(m.picker.matches)-limit)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) dropdownView() string {
	if m.dropdown == nil {
		return ""
	}
	lines := []string{
		m.styles.eyebrow.Render("SELECT OPTION"),
		m.styles.hero.Render(m.dropdown.title),
		"",
	}
	for index, option := range m.dropdown.options {
		marker := "  "
		value := option
		if index == m.dropdown.selected {
			marker = m.styles.accent.Render("› ")
			value = m.styles.selectBox.Render(option)
		}
		lines = append(lines, marker+value)
	}
	lines = append(lines, "", m.styles.help.Render("↑/↓ choose  •  Enter selects  •  Esc cancels"))
	return m.shell(strings.Join(lines, "\n"))
}

func (m *Model) formForKind(kind formKind) *operationForm {
	switch kind {
	case formProtect:
		return &m.protect
	case formRestore:
		return &m.restore
	case formHash:
		return &m.hash
	case formBenchmark:
		return &m.benchmark
	case formInspect:
		return &m.inspect
	case formVerify:
		return &m.verify
	case formList:
		return &m.list
	default:
		return &m.protect
	}
}

func screenForForm(kind formKind) screen {
	switch kind {
	case formProtect:
		return screenProtect
	case formRestore:
		return screenRestore
	case formHash:
		return screenHash
	case formBenchmark:
		return screenBenchmark
	case formInspect:
		return screenInspect
	case formVerify:
		return screenVerify
	case formList:
		return screenList
	default:
		return screenHome
	}
}
