package outbound

type CallGraphResult struct {
	Calls    map[string][]string
	CalledBy map[string][]string
}

type CallGraphPort interface {
	Build(patterns []string) (*CallGraphResult, error)
}
