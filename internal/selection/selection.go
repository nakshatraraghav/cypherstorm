// Package selection implements deterministic matching over slash-separated archive-relative paths.
package selection

import (
	"fmt"
	"path"
	"strings"
)

func Match(pattern, name string) (bool, error) {
	if pattern == "" {
		return false, fmt.Errorf("selection: empty pattern")
	}
	if path.IsAbs(pattern) || strings.Contains(pattern, `\`) {
		return false, fmt.Errorf("selection: pattern %q must be a portable relative path", pattern)
	}
	for _, part := range strings.Split(pattern, "/") {
		if part == ".." {
			return false, fmt.Errorf("selection: pattern %q contains traversal", pattern)
		}
	}
	cleanName := strings.TrimPrefix(path.Clean(name), "./")
	if cleanName == "." || strings.HasPrefix(cleanName, "../") || path.IsAbs(cleanName) {
		return false, fmt.Errorf("selection: invalid relative path %q", name)
	}
	return matchParts(strings.Split(pattern, "/"), strings.Split(cleanName, "/"))
}

func matchParts(pattern, name []string) (bool, error) {
	if len(pattern) == 0 {
		return len(name) == 0, nil
	}
	if pattern[0] == "**" {
		for len(pattern) > 1 && pattern[1] == "**" {
			pattern = pattern[1:]
		}
		if len(pattern) == 1 {
			return true, nil
		}
		for i := 0; i <= len(name); i++ {
			ok, err := matchParts(pattern[1:], name[i:])
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if len(name) == 0 {
		return false, nil
	}
	ok, err := path.Match(pattern[0], name[0])
	if err != nil {
		return false, fmt.Errorf("selection: invalid pattern %q: %w", strings.Join(pattern, "/"), err)
	}
	if !ok {
		return false, nil
	}
	return matchParts(pattern[1:], name[1:])
}
