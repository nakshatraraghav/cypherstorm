package tui

import "github.com/charmbracelet/lipgloss"

type styles struct {
	brand           lipgloss.Style
	eyebrow         lipgloss.Style
	hero            lipgloss.Style
	accent          lipgloss.Style
	label           lipgloss.Style
	muted           lipgloss.Style
	path            lipgloss.Style
	button          lipgloss.Style
	primaryButton   lipgloss.Style
	selectBox       lipgloss.Style
	toggle          lipgloss.Style
	error           lipgloss.Style
	success         lipgloss.Style
	warning         lipgloss.Style
	help            lipgloss.Style
	panel           lipgloss.Style
	header          lipgloss.Style
	footer          lipgloss.Style
	tag             lipgloss.Style
	card            lipgloss.Style
	selectedCard    lipgloss.Style
	cardTitle       lipgloss.Style
	cardDescription lipgloss.Style
	progressFill    lipgloss.Style
	progressTrack   lipgloss.Style
	progressLabel   lipgloss.Style
}

func defaultStyles() styles {
	accent := lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#F2F2F2"}
	accentSoft := lipgloss.AdaptiveColor{Light: "#E8E8E8", Dark: "#303030"}
	text := lipgloss.AdaptiveColor{Light: "#181818", Dark: "#F5F5F5"}
	muted := lipgloss.AdaptiveColor{Light: "#666666", Dark: "#A6A6A6"}
	line := lipgloss.AdaptiveColor{Light: "#C4C4C4", Dark: "#4A4A4A"}
	panel := lipgloss.AdaptiveColor{Light: "#FAFAFA", Dark: "#121212"}
	selected := lipgloss.AdaptiveColor{Light: "#EEEEEE", Dark: "#202020"}
	return styles{
		brand:           lipgloss.NewStyle().Bold(true).Foreground(accent),
		eyebrow:         lipgloss.NewStyle().Bold(true).Foreground(accent),
		hero:            lipgloss.NewStyle().Bold(true).Foreground(text),
		accent:          lipgloss.NewStyle().Bold(true).Foreground(accent),
		label:           lipgloss.NewStyle().Foreground(muted),
		muted:           lipgloss.NewStyle().Foreground(muted),
		path:            lipgloss.NewStyle().Foreground(text),
		button:          lipgloss.NewStyle().Foreground(accent).Border(lipgloss.RoundedBorder()).BorderForeground(line).Padding(0, 1),
		primaryButton:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#FAFAFA", Dark: "#121212"}).Background(accent).Padding(0, 2),
		selectBox:       lipgloss.NewStyle().Foreground(text).Background(accentSoft).Padding(0, 1),
		toggle:          lipgloss.NewStyle().Bold(true).Foreground(accent),
		error:           lipgloss.NewStyle().Bold(true).Underline(true).Foreground(text),
		success:         lipgloss.NewStyle().Bold(true).Foreground(text),
		warning:         lipgloss.NewStyle().Bold(true).Foreground(text),
		help:            lipgloss.NewStyle().Foreground(muted),
		panel:           lipgloss.NewStyle().Padding(1, 2).Border(lipgloss.RoundedBorder()).BorderForeground(line).Background(panel),
		header:          lipgloss.NewStyle().Padding(0, 1).BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(line),
		footer:          lipgloss.NewStyle().Padding(0, 1).Foreground(muted),
		tag:             lipgloss.NewStyle().Bold(true).Foreground(accent).Background(accentSoft).Padding(0, 1),
		card:            lipgloss.NewStyle().Padding(0, 1).MarginBottom(1).BorderLeft(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(line),
		selectedCard:    lipgloss.NewStyle().Padding(0, 1).MarginBottom(1).BorderLeft(true).BorderStyle(lipgloss.ThickBorder()).BorderForeground(accent).Background(selected),
		cardTitle:       lipgloss.NewStyle().Bold(true).Foreground(text),
		cardDescription: lipgloss.NewStyle().Foreground(muted),
		progressFill:    lipgloss.NewStyle().Foreground(accent),
		progressTrack:   lipgloss.NewStyle().Foreground(line),
		progressLabel:   lipgloss.NewStyle().Foreground(muted),
	}
}

func (m Model) shell(body string) string {
	width := 72
	if m.width > 0 {
		width = min(88, max(50, m.width-4))
	}
	header := m.styles.header.Width(width).Render(
		lipgloss.JoinHorizontal(lipgloss.Left,
			m.styles.brand.Render("CYPHERSTORM"),
			"  ",
			m.styles.muted.Render("SECURE FILE WORKSPACE"),
		),
	)
	panel := m.styles.panel.Width(width).Render(body)
	footer := m.styles.footer.Width(width).Render("↑/↓ navigate  ·  Enter select  ·  Esc back  ·  Ctrl+C quit")
	return lipgloss.JoinVertical(lipgloss.Left, header, "", panel, "", footer)
}
