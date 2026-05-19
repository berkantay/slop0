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
	GraphAnalysis   GraphAnalysis
}

type GraphAnalysis struct {
	Bottlenecks     []Bottleneck
	CoupledClusters []CoupledCluster
	Layers          []LayerAssignment
	LayerSkips      []LayerSkip
	Communities     []CommunityInfo
	Misplaced       []MisplacedCode
	HenryKafura     []HenryKafuraResult
	DSMPackages     []string
	DSMMatrix       [][]int
}

type Bottleneck struct {
	Function    string
	Betweenness float64
	PageRank    float64
	BlastRadius int
}

type CoupledCluster struct {
	Nodes        []string
	Size         int
	SuggestedCut string
}

type LayerAssignment struct {
	Node  string
	Layer int
}

type LayerSkip struct {
	From      string
	To        string
	FromLayer int
	ToLayer   int
	Skip      int
}

type CommunityInfo struct {
	ID      int
	Members []string
}

type MisplacedCode struct {
	Function         string
	CurrentPackage   string
	SuggestedPackage string
	EdgesToCurrent   int
	EdgesToSuggested int
}

type HenryKafuraResult struct {
	Function string
	IF       float64
	Length   int
	FanIn    int
	FanOut   int
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
