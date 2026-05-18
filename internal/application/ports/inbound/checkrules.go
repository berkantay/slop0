package inbound

import "github.com/berkantay/slop0/internal/domain"

type CheckRulesPort interface {
	Execute(pkgs []domain.Package, config *domain.RuleConfig) (*domain.Report, error)
}
