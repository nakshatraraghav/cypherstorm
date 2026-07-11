package tui

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
)

type Service interface {
	Protect(context.Context, app.ProtectRequest, app.EventSink) (app.ProtectResult, error)
	Restore(context.Context, app.RestoreRequest, app.EventSink) (app.RestoreResult, error)
	Hash(context.Context, app.HashRequest, app.EventSink) ([]app.HashResult, error)
	Benchmark(context.Context, app.BenchmarkRequest, app.EventSink) (report.Report, error)
}

func Run(ctx context.Context, service Service, input io.Reader, output io.Writer) (err error) {
	model := NewModelWithContext(ctx, service)
	program := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(input), tea.WithOutput(output), tea.WithAltScreen())
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("tui: panic: %v", recovered)
		}
	}()
	_, err = program.Run()
	return err
}
