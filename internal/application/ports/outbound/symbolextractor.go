package outbound

import "github.com/berkantay/slop0/internal/domain"

type SymbolExtractorPort interface {
	Extract(patterns []string) ([]domain.Package, error)
}
