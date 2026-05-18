package outbound

import "github.com/berkantay/slop0/internal/domain"

type RuleCheckerPort interface {
	Check(pkgs []domain.Package, config *domain.RuleConfig) (*domain.Report, error)
}
