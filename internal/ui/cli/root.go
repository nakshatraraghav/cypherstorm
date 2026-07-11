package cli

import (
	"context"
	"io"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/spf13/cobra"
)

type Service interface {
	Protect(context.Context, app.ProtectRequest, app.EventSink) (app.ProtectResult, error)
	Restore(context.Context, app.RestoreRequest, app.EventSink) (app.RestoreResult, error)
	Hash(context.Context, app.HashRequest, app.EventSink) ([]app.HashResult, error)
	Benchmark(context.Context, app.BenchmarkRequest, app.EventSink) (report.Report, error)
}

type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type RootOptions struct {
	Interactive bool
	RunTUI      func(context.Context) error
}

func NewRoot(service Service, streams Streams, version string) *cobra.Command {
	return NewRootWithOptions(service, streams, version, RootOptions{})
}

func NewRootWithOptions(service Service, streams Streams, version string, options RootOptions) *cobra.Command {
	root := &cobra.Command{
		Use:           "cypherstorm",
		Short:         "Protect, restore, hash, and benchmark files safely",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.Interactive && options.RunTUI != nil {
				return options.RunTUI(command.Context())
			}
			return command.Help()
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.AddCommand(
		newProtectCommand(service, streams),
		newRestoreCommand(service, streams),
		newHashCommand(service),
		newBenchmarkCommand(service),
		newVersionCommand(version),
	)
	if options.RunTUI != nil {
		root.AddCommand(&cobra.Command{
			Use:   "tui",
			Short: "Launch the interactive terminal interface",
			Args:  cobra.NoArgs,
			RunE: func(command *cobra.Command, _ []string) error {
				return options.RunTUI(command.Context())
			},
		})
	}
	return root
}
