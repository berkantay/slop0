package outbound

import "github.com/berkantay/slop0/internal/domain"

type RendererPort interface {
	Render(report *domain.Report) (string, error)
}
