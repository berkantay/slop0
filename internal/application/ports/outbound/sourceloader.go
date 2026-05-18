package outbound

import "github.com/berkantay/slop0/internal/domain"

type SourceLoaderPort interface {
	Load(patterns []string) ([]domain.Package, error)
}
