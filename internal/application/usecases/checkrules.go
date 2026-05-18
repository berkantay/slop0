package usecases

import "github.com/berkantay/slop0/internal/domain"

type RuleChecker interface {
	Check(pkgs []domain.Package, config *domain.RuleConfig) (*domain.Report, error)
}

type CheckRulesUseCase struct {
	checker RuleChecker
}

func NewCheckRulesUseCase(checker RuleChecker) *CheckRulesUseCase {
	return &CheckRulesUseCase{checker: checker}
}

func (uc *CheckRulesUseCase) Execute(pkgs []domain.Package, config *domain.RuleConfig) (*domain.Report, error) {
	return uc.checker.Check(pkgs, config)
}
