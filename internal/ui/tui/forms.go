package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
)

type formKind uint8

const (
	formProtect formKind = iota
	formRestore
	formHash
	formBenchmark
)

type slotKind uint8

const (
	slotInput slotKind = iota
	slotOutput
	slotCredential
	slotPassword
	slotConfirmation
	slotKeyFile
	slotCodec
	slotCipher
	slotOverwrite
	slotAlgorithm
	slotSubmit
)

type formActionKind uint8

const (
	formActionNone formActionKind = iota
	formActionBrowse
	formActionDropdown
	formActionSubmit
)

type formAction struct {
	kind formActionKind
	slot slotKind
}

type operationForm struct {
	kind         formKind
	inputPath    string
	outputDir    string
	keyFilePath  string
	password     textinput.Model
	confirmation textinput.Model
	credential   app.CredentialKind
	codecIndex   int
	cipherIndex  int
	algorithmIdx int
	overwrite    bool
	focus        int
}

func newOperationForm(kind formKind) operationForm {
	newSecret := func(placeholder string) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.CharLimit = 4096
		input.Width = 42
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '*'
		return input
	}
	form := operationForm{
		kind:         kind,
		password:     newSecret("Enter password"),
		confirmation: newSecret("Repeat password"),
		credential:   app.CredentialPassword,
	}
	form.syncFocus()
	return form
}

func (f *operationForm) slots() []slotKind {
	switch f.kind {
	case formProtect:
		slots := []slotKind{slotInput, slotOutput, slotCredential}
		if f.credential == app.CredentialPassword {
			slots = append(slots, slotPassword, slotConfirmation)
		} else {
			slots = append(slots, slotKeyFile)
		}
		return append(slots, slotCodec, slotCipher, slotOverwrite, slotSubmit)
	case formRestore:
		slots := []slotKind{slotInput, slotOutput, slotCredential}
		if f.credential == app.CredentialPassword {
			slots = append(slots, slotPassword)
		} else {
			slots = append(slots, slotKeyFile)
		}
		return append(slots, slotSubmit)
	case formHash:
		return []slotKind{slotInput, slotAlgorithm, slotSubmit}
	case formBenchmark:
		return []slotKind{slotInput, slotOutput, slotSubmit}
	default:
		return nil
	}
}

func (f *operationForm) update(message tea.Msg) (tea.Cmd, formAction) {
	key, isKey := message.(tea.KeyMsg)
	if isKey {
		slots := f.slots()
		current := slots[f.focus]
		switch key.String() {
		case "tab", "down":
			f.focus = (f.focus + 1) % len(slots)
			f.syncFocus()
			return textinput.Blink, formAction{}
		case "shift+tab", "up":
			f.focus = (f.focus - 1 + len(slots)) % len(slots)
			f.syncFocus()
			return textinput.Blink, formAction{}
		case "left":
			if f.quickAdjust(current, -1) {
				return nil, formAction{}
			}
		case "right":
			if f.quickAdjust(current, 1) {
				return nil, formAction{}
			}
		case " ":
			if f.isDropdown(current) {
				return nil, formAction{kind: formActionDropdown, slot: current}
			}
		case "enter":
			switch {
			case current == slotSubmit:
				return nil, formAction{kind: formActionSubmit, slot: current}
			case f.isBrowse(current):
				return nil, formAction{kind: formActionBrowse, slot: current}
			case f.isDropdown(current):
				return nil, formAction{kind: formActionDropdown, slot: current}
			default:
				f.focus = (f.focus + 1) % len(slots)
				f.syncFocus()
				return textinput.Blink, formAction{}
			}
		}
	}

	slot := f.slots()[f.focus]
	var command tea.Cmd
	switch slot {
	case slotPassword:
		f.password, command = f.password.Update(message)
	case slotConfirmation:
		f.confirmation, command = f.confirmation.Update(message)
	}
	return command, formAction{}
}

func (f *operationForm) quickAdjust(slot slotKind, delta int) bool {
	switch slot {
	case slotCodec:
		f.codecIndex = cycle(f.codecIndex, delta, len(compress.AllCodecs()))
		return true
	case slotCipher:
		f.cipherIndex = cycle(f.cipherIndex, delta, len(crypto.AllCipherIDs()))
		return true
	case slotAlgorithm:
		f.algorithmIdx = cycle(f.algorithmIdx, delta, len(hashing.AllIDs()))
		return true
	case slotOverwrite:
		f.overwrite = !f.overwrite
		return true
	default:
		return false
	}
}

func (f *operationForm) applyDropdown(slot slotKind, index int) {
	switch slot {
	case slotCredential:
		kind := app.CredentialPassword
		if index == 1 {
			kind = app.CredentialRawKey
		}
		if kind != f.credential {
			if kind == app.CredentialRawKey {
				f.password.SetValue("")
				f.confirmation.SetValue("")
			} else {
				f.keyFilePath = ""
			}
			f.credential = kind
			f.syncFocus()
		}
	case slotCodec:
		f.codecIndex = index
	case slotCipher:
		f.cipherIndex = index
	case slotAlgorithm:
		f.algorithmIdx = index
	}
}

func (f *operationForm) dropdownIndex(slot slotKind) int {
	switch slot {
	case slotCredential:
		if f.credential == app.CredentialRawKey {
			return 1
		}
		return 0
	case slotCodec:
		return f.codecIndex
	case slotCipher:
		return f.cipherIndex
	case slotAlgorithm:
		return f.algorithmIdx
	default:
		return 0
	}
}

func (f *operationForm) setPath(slot slotKind, path string) {
	switch slot {
	case slotInput:
		f.inputPath = path
	case slotOutput:
		f.outputDir = path
	case slotKeyFile:
		f.keyFilePath = path
	}
}

func (f operationForm) outputPreview() string {
	if f.outputDir == "" {
		return ""
	}
	switch f.kind {
	case formProtect:
		if f.inputPath == "" {
			return filepath.Join(f.outputDir, "<source>.cys")
		}
		return filepath.Join(f.outputDir, filepath.Base(f.inputPath)+".cys")
	case formRestore:
		name := strings.TrimSuffix(filepath.Base(f.inputPath), ".cys")
		if name == "" || name == "." {
			name = "restored"
		}
		return filepath.Join(f.outputDir, name+"-restored")
	case formBenchmark:
		return filepath.Join(f.outputDir, "benchmark.xlsx")
	default:
		return f.outputDir
	}
}

func cycle(current, delta, count int) int {
	return (current + delta + count) % count
}

func (f *operationForm) isBrowse(slot slotKind) bool {
	return slot == slotInput || slot == slotOutput || slot == slotKeyFile
}

func (f *operationForm) isDropdown(slot slotKind) bool {
	return slot == slotCredential || slot == slotCodec || slot == slotCipher || slot == slotAlgorithm
}

func (f *operationForm) syncFocus() {
	f.password.Blur()
	f.confirmation.Blur()
	slots := f.slots()
	if len(slots) == 0 {
		return
	}
	if f.focus >= len(slots) {
		f.focus = len(slots) - 1
	}
	switch slots[f.focus] {
	case slotPassword:
		f.password.Focus()
	case slotConfirmation:
		f.confirmation.Focus()
	}
}

func (f *operationForm) clearSecrets() {
	f.password.SetValue("")
	f.confirmation.SetValue("")
	f.keyFilePath = ""
}

func (f *operationForm) view(style styles, width int) string {
	var title, description string
	switch f.kind {
	case formProtect:
		title, description = "Protect", "Archive, compress, and encrypt"
	case formRestore:
		title, description = "Restore", "Authenticate and recover protected data"
	case formHash:
		title, description = "Hash", "Calculate digests for files or folders"
	case formBenchmark:
		title, description = "Benchmark", "Compare every codec and cipher combination"
	}
	lines := []string{style.brand.Render("CYPHERSTORM"), style.title.Render(title), style.muted.Render(description), ""}
	for index, slot := range f.slots() {
		focused := index == f.focus
		lines = append(lines, f.renderSlot(slot, focused, style, width))
	}
	if preview := f.outputPreview(); preview != "" && f.kind != formHash {
		lines = append(lines, "", style.muted.Render("Will create  ")+style.path.Render(shortPath(preview, max(16, width-20))))
	}
	lines = append(lines, "", style.help.Render("tab/shift+tab move  •  enter opens  •  esc goes back"))
	return strings.Join(lines, "\n")
}

func (f *operationForm) renderSlot(slot slotKind, focused bool, style styles, width int) string {
	marker := "  "
	if focused {
		marker = style.accent.Render("› ")
	}
	row := func(label, value string) string {
		content := style.label.Render(fmt.Sprintf("%-17s", label)) + value
		if focused {
			return marker + style.focused.Render(content)
		}
		return marker + content
	}
	selected := func(value string) string {
		return style.selectBox.Render(value + "  ▾")
	}
	pathValue := func(value, empty string) string {
		if value == "" {
			return style.muted.Render(empty) + "  " + style.button.Render(" Browse ")
		}
		available := max(14, width-40)
		return style.path.Render(shortPath(value, available)) + "  " + style.button.Render(" Change ")
	}

	switch slot {
	case slotInput:
		return row("Source", pathValue(f.inputPath, "Not selected"))
	case slotOutput:
		return row("Destination", pathValue(f.outputDir, "Not selected"))
	case slotCredential:
		kind := "Password"
		if f.credential == app.CredentialRawKey {
			kind = "Raw key file"
		}
		return row("Credential", selected(kind))
	case slotPassword:
		return row("Password", f.password.View())
	case slotConfirmation:
		return row("Confirm", f.confirmation.View())
	case slotKeyFile:
		return row("Key file", pathValue(f.keyFilePath, "Not selected"))
	case slotCodec:
		return row("Compression", selected(string(compress.AllCodecs()[f.codecIndex].ID())))
	case slotCipher:
		return row("Encryption", selected(string(crypto.AllCipherIDs()[f.cipherIndex])))
	case slotOverwrite:
		value := "Off"
		if f.overwrite {
			value = "On"
		}
		return row("Overwrite", style.toggle.Render(value))
	case slotAlgorithm:
		return row("Algorithm", selected(string(hashing.AllIDs()[f.algorithmIdx])))
	case slotSubmit:
		return marker + style.primaryButton.Render(" Continue ")
	default:
		return ""
	}
}

func shortPath(path string, limit int) string {
	runes := []rune(path)
	if len(runes) <= limit {
		return path
	}
	if limit <= 1 {
		return "…"
	}
	base := []rune(filepath.Base(path))
	if len(base)+2 < limit {
		prefixLength := limit - len(base) - 2
		return string(runes[:prefixLength]) + "…/" + string(base)
	}
	return "…" + string(runes[len(runes)-(limit-1):])
}
