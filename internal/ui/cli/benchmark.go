package cli

import (
	"errors"
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/spf13/cobra"
)

type benchmarkOptions struct {
	inputPath  string
	outputPath string
}

func newBenchmarkCommand(service Service) *cobra.Command {
	options := benchmarkOptions{}
	command := &cobra.Command{
		Use:   "benchmark",
		Short: "Benchmark every compression and cipher combination",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			result, benchmarkErr := service.Benchmark(command.Context(), app.BenchmarkRequest{
				InputPath:  options.inputPath,
				OutputPath: options.outputPath,
			}, nil)
			renderErr := report.WriteTextReport(command.OutOrStdout(), &result)
			if renderErr == nil && options.outputPath != "" {
				_, renderErr = fmt.Fprintf(command.OutOrStdout(), "\nExcel report: %s\n", options.outputPath)
			}
			return errors.Join(benchmarkErr, renderErr)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.inputPath, "input-path", "", "input file or directory to benchmark")
	flags.StringVar(&options.outputPath, "output-path", "", "XLSX report output path")
	return command
}
