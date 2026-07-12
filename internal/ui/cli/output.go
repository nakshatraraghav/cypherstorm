package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	"github.com/spf13/cobra"
)

var operationCounter atomic.Uint64

type progressEvent struct {
	SchemaVersion int       `json:"schema_version"`
	OperationID   string    `json:"operation_id"`
	Operation     string    `json:"operation"`
	Phase         app.Phase `json:"phase"`
	Current       int64     `json:"current,omitempty"`
	Total         int64     `json:"total,omitempty"`
	Unit          string    `json:"unit,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}

func outputFormat(cmd *cobra.Command) string {
	v, e := cmd.Flags().GetString("output-format")
	if e == nil && v != "" {
		return v
	}
	v, _ = cmd.Root().PersistentFlags().GetString("output-format")
	return v
}
func progressMode(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("progress")
	if v == "" {
		v, _ = cmd.Root().PersistentFlags().GetString("progress")
	}
	return v
}
func eventSink(cmd *cobra.Command, operation string) app.EventSink {
	mode := progressMode(cmd)
	if mode == "none" || mode == "" || mode == "auto" {
		return nil
	}
	id := fmt.Sprintf("local-%d", operationCounter.Add(1))
	writer := cmd.ErrOrStderr()
	return func(event app.Event) {
		if mode == "json" {
			_ = json.NewEncoder(writer).Encode(progressEvent{SchemaVersion: 1, OperationID: id, Operation: operation, Phase: event.Phase, Current: event.Current, Total: event.Total, Unit: "bytes", Detail: event.Detail})
			return
		}
		_, _ = fmt.Fprintf(writer, "%s: %s", operation, event.Phase)
		if event.Total > 0 {
			_, _ = fmt.Fprintf(writer, " %d/%d", event.Current, event.Total)
		}
		if event.Detail != "" {
			_, _ = fmt.Fprintf(writer, " %s", event.Detail)
		}
		_, _ = fmt.Fprintln(writer)
	}
}
func writeResult(cmd *cobra.Command, operation string, result any, text func(io.Writer) error) error {
	if outputFormat(cmd) == "json" {
		return writeJSON(cmd, operation, result)
	}
	return text(cmd.OutOrStdout())
}
