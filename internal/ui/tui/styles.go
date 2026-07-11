package tui

import "github.com/charmbracelet/lipgloss"

type styles struct {
	brand         lipgloss.Style
	title         lipgloss.Style
	accent        lipgloss.Style
	label         lipgloss.Style
	muted         lipgloss.Style
	path          lipgloss.Style
	focused       lipgloss.Style
	button        lipgloss.Style
	primaryButton lipgloss.Style
	selectBox     lipgloss.Style
	toggle        lipgloss.Style
	error         lipgloss.Style
	success       lipgloss.Style
	help          lipgloss.Style
	panel         lipgloss.Style
	modal         lipgloss.Style
}

func defaultStyles() styles {
	warm := lipgloss.AdaptiveColor{Light: "#B85C38", Dark: "#D97757"}
	warmSoft := lipgloss.AdaptiveColor{Light: "#F3E4DB", Dark: "#3B2924"}
	text := lipgloss.AdaptiveColor{Light: "#2D2926", Dark: "#E8E3D9"}
	muted := lipgloss.AdaptiveColor{Light: "#746E69", Dark: "#9A938C"}
	line := lipgloss.AdaptiveColor{Light: "#D8D2CC", Dark: "#4B4642"}
	return styles{
		brand:         lipgloss.NewStyle().Bold(true).Foreground(warm),
		title:         lipgloss.NewStyle().Bold(true).Foreground(text),
		accent:        lipgloss.NewStyle().Bold(true).Foreground(warm),
		label:         lipgloss.NewStyle().Foreground(muted),
		muted:         lipgloss.NewStyle().Foreground(muted),
		path:          lipgloss.NewStyle().Foreground(text),
		focused:       lipgloss.NewStyle().Foreground(text),
		button:        lipgloss.NewStyle().Foreground(warm).Border(lipgloss.RoundedBorder()).BorderForeground(line).Padding(0, 1),
		primaryButton: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#1F1815"}).Background(warm).Padding(0, 2),
		selectBox:     lipgloss.NewStyle().Foreground(text).Background(warmSoft).Padding(0, 1),
		toggle:        lipgloss.NewStyle().Bold(true).Foreground(warm),
		error:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#A33A2B", Dark: "#FF8D7A"}),
		success:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#357A55", Dark: "#79C99E"}),
		help:          lipgloss.NewStyle().Foreground(muted),
		panel:         lipgloss.NewStyle().Padding(1, 2).BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).BorderForeground(warm),
		modal:         lipgloss.NewStyle().Padding(1, 2).Border(lipgloss.RoundedBorder()).BorderForeground(line),
	}
}
