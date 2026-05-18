package outbound

import "github.com/berkantay/slop0/internal/domain"

type CrossRefPort interface {
	Resolve(pkgs []domain.Package) ([]domain.Package, error)
}
