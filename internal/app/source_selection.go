package app

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/nakshatraraghav/cypherstorm/internal/storage/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/selection"
)

type SelectionPreview struct {
	IncludedEntries int   `json:"included_entries"`
	ExcludedEntries int   `json:"excluded_entries"`
	IncludedBytes   int64 `json:"included_bytes"`
	ExcludedBytes   int64 `json:"excluded_bytes"`
}

func createSelectionOptions(includes, excludes []string, excludeVCS, excludeCache bool, preview *SelectionPreview) (archive.CreateOptions, error) {
	patterns := append([]string(nil), excludes...)
	if excludeVCS {
		patterns = append(patterns, "**/.git/**", "**/.hg/**", "**/.svn/**")
	}
	if excludeCache {
		patterns = append(patterns, "**/.cache/**", "**/__pycache__/**", "**/node_modules/**")
	}
	for _, p := range append(append([]string(nil), includes...), patterns...) {
		if _, err := selection.Match(p, "validation/path"); err != nil {
			return archive.CreateOptions{}, err
		}
	}
	selectFn := func(name string, info fs.FileInfo) (archive.SelectionDecision, error) {
		for _, p := range patterns {
			ok, err := selection.Match(p, name)
			if err != nil {
				return 0, err
			}
			if ok {
				if info.IsDir() {
					return archive.SelectionPrune, nil
				}
				return archive.SelectionExclude, nil
			}
		}
		if len(includes) == 0 {
			return archive.SelectionInclude, nil
		}
		for _, p := range includes {
			ok, err := selection.Match(p, name)
			if err != nil {
				return 0, err
			}
			if ok {
				return archive.SelectionInclude, nil
			}
			if info.IsDir() && couldContain(p, name) {
				return archive.SelectionInclude, nil
			}
		}
		return archive.SelectionExclude, nil
	}
	visit := func(_ string, info fs.FileInfo, d archive.SelectionDecision) {
		if preview == nil {
			return
		}
		if d == archive.SelectionInclude {
			preview.IncludedEntries++
			if info.Mode().IsRegular() {
				preview.IncludedBytes += info.Size()
			}
		} else {
			preview.ExcludedEntries++
			if info.Mode().IsRegular() {
				preview.ExcludedBytes += info.Size()
			}
		}
	}
	return archive.CreateOptions{Select: selectFn, Visit: visit}, nil
}
func couldContain(pattern, dir string) bool {
	literal := pattern
	for i, r := range literal {
		if strings.ContainsRune("*?[", r) {
			literal = literal[:i]
			break
		}
	}
	literal = strings.TrimSuffix(literal, "/")
	return literal == dir || strings.HasPrefix(literal, dir+"/") || strings.HasPrefix(pattern, "**/")
}
func validateNonemptySelection(p SelectionPreview) error {
	if p.IncludedEntries == 0 {
		return fmt.Errorf("app: selection is empty")
	}
	return nil
}
