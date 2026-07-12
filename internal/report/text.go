package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"
)

// WriteTextReport renders r as a tabwriter-aligned text report to w:
// successes sorted by time, successes sorted by compression ratio
// (descending), then a labeled failures section listing each failed
// combination and its error. It sorts copies of r.Successes, never
// mutating the caller's slice, never panics, and renders a "no successful
// combinations" message when r has no successes (failures still render).
func WriteTextReport(w io.Writer, r *Report) error {
	if err := r.validate(); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', tabwriter.TabIndent)

	byTime := append([]Success(nil), r.Successes...)
	sort.SliceStable(byTime, func(i, j int) bool {
		return byTime[i].Duration < byTime[j].Duration
	})

	byRatio := append([]Success(nil), r.Successes...)
	sort.SliceStable(byRatio, func(i, j int) bool {
		return byRatio[i].CompressionRatio > byRatio[j].CompressionRatio
	})

	fmt.Fprintln(tw, "Results Sorted by Time:")
	fmt.Fprintln(tw, "=====================")
	writeSuccessSection(tw, byTime)

	fmt.Fprintln(tw, "\nResults Sorted by Compression Ratio:")
	fmt.Fprintln(tw, "==================================")
	writeSuccessSection(tw, byRatio)

	fmt.Fprintln(tw, "\nFailed Combinations:")
	fmt.Fprintln(tw, "====================")
	if len(r.Failures) == 0 {
		fmt.Fprintln(tw, "no failed combinations")
	} else {
		fmt.Fprintln(tw, "Compression\tCipher\tError")
		fmt.Fprintln(tw, "-----------\t------\t-----")
		for _, f := range r.Failures {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Combination.Codec, f.Combination.Cipher, f.Err.Error())
		}
	}

	return tw.Flush()
}

func writeSuccessSection(tw *tabwriter.Writer, results []Success) {
	if len(results) == 0 {
		fmt.Fprintln(tw, "no successful combinations")
		return
	}

	fmt.Fprintln(tw, "Compression\tCipher\tTime\tRatio\tOriginal Size\tFinal Size")
	fmt.Fprintln(tw, "-----------\t------\t----\t-----\t-------------\t----------")
	for _, s := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.2fx\t%d bytes\t%d bytes\n",
			s.Combination.Codec,
			s.Combination.Cipher,
			s.Duration.Round(time.Millisecond),
			s.CompressionRatio,
			s.OriginalSize,
			s.FinalSize,
		)
	}
}
