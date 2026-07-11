package app

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
)

type BatchProtectRequest struct {
	Inputs          []string
	Destination     string
	Credential      Credential
	Cipher          crypto.CipherID
	Codec           compress.CompressionID
	ContinueOnError bool
}
type BatchRestoreRequest struct {
	Inputs          []string
	Destination     string
	Credential      Credential
	ContinueOnError bool
	Conflict        ConflictPolicy
}
type BatchItemResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type BatchResult struct {
	Items     []BatchItemResult `json:"items"`
	Succeeded int               `json:"succeeded"`
	Failed    int               `json:"failed"`
}

func (s *Service) BatchProtect(ctx context.Context, req BatchProtectRequest, sink EventSink) (BatchResult, error) {
	inputs, outputs, err := batchPaths(req.Inputs, req.Destination, true)
	if err != nil {
		return BatchResult{}, err
	}
	var result BatchResult
	for i, input := range inputs {
		r, e := s.Protect(ctx, ProtectRequest{InputPath: input, OutputPath: outputs[i], Credential: req.Credential, Cipher: req.Cipher, Codec: req.Codec}, sink)
		item := BatchItemResult{Input: input, Output: outputs[i], Status: "success"}
		if e != nil {
			item.Status, item.Error = "error", e.Error()
			result.Failed++
		} else {
			item.Output = r.OutputPath
			result.Succeeded++
		}
		result.Items = append(result.Items, item)
		if e != nil && !req.ContinueOnError {
			return result, e
		}
	}
	return result, nil
}
func (s *Service) BatchRestore(ctx context.Context, req BatchRestoreRequest, sink EventSink) (BatchResult, error) {
	inputs, outputs, err := batchPaths(req.Inputs, req.Destination, false)
	if err != nil {
		return BatchResult{}, err
	}
	var result BatchResult
	for i, input := range inputs {
		r, e := s.Restore(ctx, RestoreRequest{InputPath: input, OutputPath: outputs[i], Credential: req.Credential, Conflict: req.Conflict}, sink)
		item := BatchItemResult{Input: input, Output: outputs[i], Status: "success"}
		if e != nil {
			item.Status, item.Error = "error", e.Error()
			result.Failed++
		} else {
			item.Output = r.OutputPath
			result.Succeeded++
		}
		result.Items = append(result.Items, item)
		if e != nil && !req.ContinueOnError {
			return result, e
		}
	}
	return result, nil
}
func batchPaths(given []string, destination string, protect bool) ([]string, []string, error) {
	if len(given) == 0 {
		return nil, nil, fmt.Errorf("app: batch requires at least one input")
	}
	if destination == "" {
		return nil, nil, fmt.Errorf("app: batch destination is required")
	}
	inputs := append([]string(nil), given...)
	sort.Strings(inputs)
	outputs := make([]string, len(inputs))
	seen := map[string]bool{}
	for i, input := range inputs {
		name := filepath.Base(input)
		if protect {
			name += ".cys"
		} else {
			name = strings.TrimSuffix(name, ".cys")
		}
		outputs[i] = filepath.Join(destination, name)
		if seen[outputs[i]] {
			return nil, nil, fmt.Errorf("app: batch output collision at %q", outputs[i])
		}
		seen[outputs[i]] = true
	}
	return inputs, outputs, nil
}
