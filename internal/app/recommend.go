package app

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/nakshatraraghav/cypherstorm/internal/report"
)

type RecommendRequest struct {
	InputPath string
	Optimize  string
	Mode      string
}
type RecommendResult struct {
	Combination report.Combination `json:"combination"`
	Optimize    string             `json:"optimize"`
	Mode        string             `json:"mode"`
	Estimated   bool               `json:"estimated"`
	Report      report.Report      `json:"report"`
}

func (s *Service) Recommend(ctx context.Context, req RecommendRequest, sink EventSink) (RecommendResult, error) {
	if req.Optimize == "" {
		req.Optimize = "balanced"
	}
	if req.Mode == "" {
		req.Mode = "full"
	}
	switch req.Optimize {
	case "balanced", "size", "protect-speed", "restore-speed":
	default:
		return RecommendResult{}, fmt.Errorf("app: invalid optimization goal %q", req.Optimize)
	}
	if req.Mode != "full" && req.Mode != "sample" {
		return RecommendResult{}, fmt.Errorf("app: invalid recommendation mode %q", req.Mode)
	}
	r, err := s.Benchmark(ctx, BenchmarkRequest{InputPath: req.InputPath}, sink)
	if err != nil && len(r.Successes) == 0 {
		return RecommendResult{}, err
	}
	if len(r.Successes) == 0 {
		return RecommendResult{}, ErrNoBenchmarkSuccess
	}
	successes := append([]report.Success(nil), r.Successes...)
	sort.Slice(successes, func(i, j int) bool {
		a, b := successes[i].Combination, successes[j].Combination
		if a.Codec != b.Codec {
			return a.Codec < b.Codec
		}
		return a.Cipher < b.Cipher
	})
	best := successes[0]
	score := func(x report.Success) float64 {
		switch req.Optimize {
		case "size":
			return -float64(x.FinalSize)
		case "protect-speed", "restore-speed":
			return -float64(x.Duration)
		default:
			ratio := x.CompressionRatio
			if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
				ratio = 0
			}
			return ratio*1e9 - float64(x.Duration)
		}
	}
	bestScore := score(best)
	for _, candidate := range successes[1:] {
		if v := score(candidate); v > bestScore {
			best, bestScore = candidate, v
		}
	}
	return RecommendResult{Combination: best.Combination, Optimize: req.Optimize, Mode: req.Mode, Estimated: req.Mode == "sample", Report: r}, nil
}
