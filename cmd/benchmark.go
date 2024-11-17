package cmd

import (
	"log"

	"github.com/nakshatraraghav/cypherstorm/internal/pipeline"
	"github.com/spf13/cobra"
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Benchmark all combination of algorithms",
	Long:  "Generate performance report for all compression and encryption combinations",
	Run: func(cmd *cobra.Command, args []string) {
		err := pipeline.BenchmarkGenerator(inputPath)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(benchmarkCmd)

	benchmarkCmd.Flags().StringVar(&inputPath, "input-path", "", "input path of the files to benchmark")
	benchmarkCmd.MarkFlagRequired("input-path")

}
