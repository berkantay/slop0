package domain

type Report struct {
	Packages        []Package
	DesignPatterns  []DesignPattern
	Circulars       []CircularDep
	LayerViolations []LayerViolation
	PatternIssues   []PatternIssue
	Duplications    []Duplication
	PkgMetrics      []PackageMetrics
	TypeMetrics     []TypeMetrics
	EntryPoints     []EntryPoint
	ExternalDeps    []ExternalDep
	Hotspots        []Hotspot
	DataFlows       []DataFlowPath
	Summary         Summary
}

type EntryPoint struct {
	Kind    string
	Route   string
	Handler string
	File    string
	Line    int
}

type ExternalDep struct {
	Kind    string
	Package string
	Type    string
	UsedBy  string
}

type Hotspot struct {
	Function    string
	PageRank    float64
	BlastRadius int
}

type DataFlowPath struct {
	Entry string
	Chain []string
	Sink  string
}

type Summary struct {
	TotalPackages  int
	TotalFunctions int
	TotalTypes     int
	EntryPoints    []string
	ExternalDeps   []string
	TopHotspots    []string
	RoleCounts     map[string]int
	IssueCount     int
	PatternCount   int
	DataFlowCount  int
}

type Finding struct {
	Category   string
	Message    string
	Confidence Confidence
	Location   Location
}

type DesignPattern struct {
	Name         string
	Description  string
	Participants []PatternParticipant
	Confidence   Confidence
}

type PatternParticipant struct {
	Role    string
	Type    string
	Package string
	File    string
	Line    int
}

type Location struct {
	File string
	Line int
}

type CircularDep struct {
	Chain     []string
	Locations []Location
}

type LayerViolation struct {
	From         string
	To           string
	ExpectedPath string
	Location     Location
}

type PatternIssue struct {
	Category   string
	Dominant   string
	Violation  string
	Confidence Confidence
	Locations  []Location
}

type Duplication struct {
	FuncA       string
	FuncB       string
	Similarity  float64
	Description string
	Locations   [2]Location
}
