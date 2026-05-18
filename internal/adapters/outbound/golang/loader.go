package golang

import "github.com/berkantay/slop0/internal/domain"

type SourceLoader struct{}

func NewSourceLoader() *SourceLoader {
	return &SourceLoader{}
}

func (l *SourceLoader) Load(patterns []string) ([]domain.Package, error) {
	// TODO: Phase 2 — implement with go/packages
	return nil, nil
}
