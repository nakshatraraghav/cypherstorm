package app

import (
	"context"

	configpkg "github.com/nakshatraraghav/cypherstorm/internal/config"
)

type ConfigResult struct {
	Path          string            `json:"path"`
	Configuration configpkg.File    `json:"configuration"`
	Effective     *configpkg.Policy `json:"effective,omitempty"`
}

func (s *Service) ConfigShow(ctx context.Context, effective bool) (ConfigResult, error) {
	if err := ctx.Err(); err != nil {
		return ConfigResult{}, err
	}
	path, err := configpkg.Path()
	if err != nil {
		return ConfigResult{}, err
	}
	cfg, err := configpkg.Load(path)
	if err != nil {
		return ConfigResult{}, err
	}
	r := ConfigResult{Path: path, Configuration: cfg}
	if effective {
		p, err := configpkg.Resolve(cfg, "")
		if err != nil {
			return ConfigResult{}, err
		}
		r.Effective = &p
	}
	return r, nil
}
func (s *Service) ConfigValidate(ctx context.Context) (ConfigResult, error) {
	return s.ConfigShow(ctx, true)
}
func (s *Service) PolicyShow(ctx context.Context, name string) (configpkg.Policy, error) {
	if err := ctx.Err(); err != nil {
		return configpkg.Policy{}, err
	}
	cfg, err := configpkg.Load("")
	if err != nil {
		return configpkg.Policy{}, err
	}
	return configpkg.Resolve(cfg, name)
}
