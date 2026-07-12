package tui

import (
	"os"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	fzf "github.com/junegunn/fzf/src/algo"
	"github.com/junegunn/fzf/src/util"
)

const maxFuzzyMatches = 200

func init() {
	// fzf's matcher has a package-level scoring scheme. Path mode gives
	// directory separators the same boundary preference as the fzf CLI.
	fzf.Init("path")
}

type fuzzyMatch struct {
	index int
	name  string
	isDir bool
	score int
}

type fuzzyMatchesMsg struct {
	generation uint64
	directory  string
	query      string
	matches    []fuzzyMatch
	err        error
}

// fuzzySearch ranks directory entries with fzf's FuzzyMatchV2 engine. It runs
// as a Bubble Tea command so directory enumeration and matching never block
// the terminal update loop.
func fuzzySearch(generation uint64, directory, query string, showHidden bool) tea.Cmd {
	return func() tea.Msg {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return fuzzyMatchesMsg{generation: generation, directory: directory, query: query, err: err}
		}
		sort.Slice(entries, func(left, right int) bool {
			if entries[left].IsDir() == entries[right].IsDir() {
				return entries[left].Name() < entries[right].Name()
			}
			return entries[left].IsDir()
		})
		pattern := []rune(strings.ToLower(strings.TrimSpace(query)))
		matches := make([]fuzzyMatch, 0, len(entries))
		for index, entry := range entries {
			if !showHidden && isHiddenName(entry.Name()) {
				continue
			}
			chars := util.RunesToChars([]rune(entry.Name()))
			result, _ := fzf.FuzzyMatchV2(false, true, true, &chars, pattern, false, nil)
			if result.Start < 0 {
				continue
			}
			matches = append(matches, fuzzyMatch{index: index, name: entry.Name(), isDir: entry.IsDir(), score: result.Score})
		}
		sort.SliceStable(matches, func(left, right int) bool {
			if matches[left].score == matches[right].score {
				return strings.ToLower(matches[left].name) < strings.ToLower(matches[right].name)
			}
			return matches[left].score > matches[right].score
		})
		if len(matches) > maxFuzzyMatches {
			matches = matches[:maxFuzzyMatches]
		}
		return fuzzyMatchesMsg{generation: generation, directory: directory, query: query, matches: matches}
	}
}

func isHiddenName(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}
