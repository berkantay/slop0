package outbound

import "github.com/berkantay/slop0/internal/domain"

type RuleConfigPort interface {
	Load(path string) (*domain.RuleConfig, error)
}
