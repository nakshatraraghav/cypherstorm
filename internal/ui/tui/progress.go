package tui

import (
	"fmt"
	"strings"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
)

const progressBarWidth = 32

// progressFillWidth returns the completed portion of a fixed-width bar.
// Unknown and invalid totals intentionally render as an empty, indeterminate bar.
func progressFillWidth(current, total int64, width int) int {
	if total <= 0 || width <= 0 {
		return 0
	}
	if current <= 0 {
		return 0
	}
	if current >= total {
		return width
	}
	filled := int(float64(current) / float64(total) * float64(width))
	if filled < 0 {
		return 0
	}
	if filled > width {
		return width
	}
	return filled
}

func renderProgress(event app.Event, style styles) string {
	filled := progressFillWidth(event.Current, event.Total, progressBarWidth)
	bar := style.progressFill.Render(strings.Repeat("█", filled)) +
		style.progressTrack.Render(strings.Repeat("░", progressBarWidth-filled))
	if event.Total <= 0 {
		return bar + "  " + style.progressLabel.Render("Working — progress is not measurable for this phase")
	}
	current := event.Current
	if current < 0 {
		current = 0
	}
	if current > event.Total {
		current = event.Total
	}
	percent := int(float64(current) / float64(event.Total) * 100)
	return bar + "  " + style.progressLabel.Render(fmt.Sprintf("%3d%%  %d / %d", percent, current, event.Total))
}
