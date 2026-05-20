package domain

type PackageMetrics struct {
	Path           string
	Ca             int     // afferent coupling — who depends on me
	Ce             int     // efferent coupling — who do I depend on
	Instability    float64 // Ce / (Ca + Ce), 0=stable 1=unstable
	Abstractness   float64 // interfaces / total types
	Distance       float64 // |A + I - 1|, 0=ideal
	TypeCount      int
	InterfaceCount int
}

type TypeMetrics struct {
	Name        string
	Package     string
	FanIn       int
	FanOut      int
	FieldCount  int
	MethodCount int
	ImplementsCount int
	HasExternalDep  bool
	LCOM4       int
}

type Confidence float64

const (
	ConfidenceHigh   Confidence = 0.8
	ConfidenceMedium Confidence = 0.5
	ConfidenceLow    Confidence = 0.3
)

func (c Confidence) Label() string {
	switch {
	case c >= 0.8:
		return "high"
	case c >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func NoisyOR(signals ...float64) float64 {
	product := 1.0
	for _, s := range signals {
		if s < 0 {
			s = 0
		}
		if s > 1 {
			s = 1
		}
		product *= (1 - s)
	}
	return 1 - product
}
