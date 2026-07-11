package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
)

type pickerState struct {
	model        filepicker.Model
	form         formKind
	slot         slotKind
	returnScreen screen
	title        string
	directories  bool
	ready        bool
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
	m.picker = &pickerState{
		model:        picker,
		form:         kind,
		slot:         slot,
		returnScreen: screenForForm(kind),
		title:        title,
		directories:  picker.DirAllowed,
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

func (m Model) updatePicker(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.picker == nil {
		m.screen = screenHome
		return m, nil
	}
	if key, ok := message.(tea.KeyMsg); ok {
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

	picker, command := m.picker.model.Update(message)
	m.picker.model = picker
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
		m.styles.brand.Render("CYPHERSTORM"),
		m.styles.title.Render(m.picker.title),
	}
	if !m.picker.ready {
		lines = append(lines, "", m.styles.muted.Render("Loading folder…"), "", m.styles.help.Render("esc cancels"))
		return m.styles.modal.Render(strings.Join(lines, "\n"))
	}
	lines = append(lines,
		m.styles.success.Render("Ready — "+m.picker.title),
		m.styles.muted.Render(m.picker.model.CurrentDirectory),
		"",
		m.picker.model.View(),
		"",
	)
	if m.picker.directories {
		lines = append(lines, m.styles.help.Render("enter selects  •  right opens folder  •  s selects this folder  •  esc cancels"))
	} else {
		lines = append(lines, m.styles.help.Render("enter selects  •  right opens folder  •  esc cancels"))
	}
	if m.validation != "" {
		lines = append(lines, "", m.styles.error.Render(m.validation))
	}
	return m.styles.modal.Render(strings.Join(lines, "\n"))
}

func (m Model) dropdownView() string {
	if m.dropdown == nil {
		return ""
	}
	lines := []string{m.styles.brand.Render("CYPHERSTORM"), m.styles.title.Render(m.dropdown.title), ""}
	for index, option := range m.dropdown.options {
		marker := "  "
		value := option
		if index == m.dropdown.selected {
			marker = m.styles.accent.Render("› ")
			value = m.styles.selectBox.Render(option)
		}
		lines = append(lines, marker+value)
	}
	lines = append(lines, "", m.styles.help.Render("up/down choose  •  enter selects  •  esc cancels"))
	return m.styles.modal.Render(strings.Join(lines, "\n"))
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
