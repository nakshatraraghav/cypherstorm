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
	type state struct{ patternIndex, nameIndex int }
	memo := make(map[state]bool, len(pattern)*len(name))
	seen := make(map[state]bool, len(pattern)*len(name))
	var visit func(int, int) (bool, error)
	visit = func(patternIndex, nameIndex int) (bool, error) {
		for patternIndex+1 < len(pattern) && pattern[patternIndex] == "**" && pattern[patternIndex+1] == "**" {
			patternIndex++
		}
		current := state{patternIndex, nameIndex}
		if seen[current] {
			return memo[current], nil
		}
		var matched bool
		switch {
		case patternIndex == len(pattern):
			matched = nameIndex == len(name)
		case pattern[patternIndex] == "**":
			if patternIndex+1 == len(pattern) {
				matched = true
				break
			}
			for nextNameIndex := nameIndex; nextNameIndex <= len(name); nextNameIndex++ {
				ok, err := visit(patternIndex+1, nextNameIndex)
				if err != nil {
					return false, err
				}
				if ok {
					matched = true
					break
				}
			}
		case nameIndex < len(name):
			ok, err := path.Match(pattern[patternIndex], name[nameIndex])
			if err != nil {
				return false, fmt.Errorf("selection: invalid pattern %q: %w", strings.Join(pattern, "/"), err)
			}
			if ok {
				matched, err = visit(patternIndex+1, nameIndex+1)
				if err != nil {
					return false, err
				}
			}
		}
		seen[current] = true
		memo[current] = matched
		return matched, nil
	}
	return visit(0, 0)
}
