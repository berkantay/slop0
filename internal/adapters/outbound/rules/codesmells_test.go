package rules

import (
	"testing"

	"github.com/berkantay/slop0/internal/domain"
)

func TestFeatureEnvy(t *testing.T) {
	tests := []struct {
		name    string
		pkgs    []domain.Package
		wantMin int
	}{
		{
			"function envies another package",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:    "Process",
							Package: "pkg/a",
							Calls:   []string{"pkg/b.Read", "pkg/b.Write", "pkg/b.Close", "pkg/b.Flush"},
						},
					},
				},
				{
					Path: "pkg/b",
					Functions: []domain.Function{
						{Name: "Read", Package: "pkg/b"},
						{Name: "Write", Package: "pkg/b"},
						{Name: "Close", Package: "pkg/b"},
						{Name: "Flush", Package: "pkg/b"},
					},
				},
			},
			1,
		},
		{
			"function calls own package mostly",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:    "Process",
							Package: "pkg/a",
							Calls:   []string{"pkg/a.Helper1", "pkg/a.Helper2", "pkg/a.Helper3", "pkg/b.Read"},
						},
						{Name: "Helper1", Package: "pkg/a"},
						{Name: "Helper2", Package: "pkg/a"},
						{Name: "Helper3", Package: "pkg/a"},
					},
				},
				{
					Path: "pkg/b",
					Functions: []domain.Function{
						{Name: "Read", Package: "pkg/b"},
					},
				},
			},
			0,
		},
		{
			"no calls at all",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{Name: "Process", Package: "pkg/a"},
					},
				},
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &CodeSmellDetector{}
			issues := d.detectFeatureEnvy(tt.pkgs)
			if len(issues) < tt.wantMin {
				t.Errorf("detectFeatureEnvy() returned %d issues, want at least %d", len(issues), tt.wantMin)
			}
		})
	}
}

func TestMiddleMan(t *testing.T) {
	tests := []struct {
		name    string
		pkgs    []domain.Package
		wantMin int
	}{
		{
			"cross-package middle man",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:     "Proxy",
							Package:  "pkg/a",
							Calls:    []string{"pkg/b.DoWork"},
							CalledBy: []string{"pkg/c.Handler1", "pkg/c.Handler2"},
						},
					},
				},
				{
					Path: "pkg/b",
					Functions: []domain.Function{
						{Name: "DoWork", Package: "pkg/b"},
					},
				},
				{
					Path: "pkg/c",
					Functions: []domain.Function{
						{Name: "Handler1", Package: "pkg/c"},
						{Name: "Handler2", Package: "pkg/c"},
					},
				},
			},
			1,
		},
		{
			"same-package helper not flagged",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:     "Helper",
							Package:  "pkg/a",
							Calls:    []string{"pkg/a.Internal"},
							CalledBy: []string{"pkg/a.Main"},
						},
						{Name: "Internal", Package: "pkg/a"},
						{Name: "Main", Package: "pkg/a"},
					},
				},
			},
			0,
		},
		{
			"multiple calls not middle man",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:     "Orchestrator",
							Package:  "pkg/a",
							Calls:    []string{"pkg/b.Step1", "pkg/b.Step2"},
							CalledBy: []string{"pkg/c.Caller1", "pkg/c.Caller2"},
						},
					},
				},
			},
			0,
		},
		{
			"constructor excluded",
			[]domain.Package{
				{
					Path: "pkg/a",
					Functions: []domain.Function{
						{
							Name:     "NewService",
							Package:  "pkg/a",
							Calls:    []string{"pkg/b.Init"},
							CalledBy: []string{"pkg/c.Setup1", "pkg/c.Setup2"},
						},
					},
				},
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &CodeSmellDetector{}
			issues := d.detectMiddleMan(tt.pkgs)
			if len(issues) < tt.wantMin {
				t.Errorf("detectMiddleMan() returned %d issues, want at least %d", len(issues), tt.wantMin)
			}
		})
	}
}

func TestShotgunSurgery(t *testing.T) {
	tests := []struct {
		name    string
		pkgs    []domain.Package
		wantMin int
	}{
		{
			"many callers across packages",
			[]domain.Package{
				{
					Path: "pkg/core",
					Functions: []domain.Function{
						{
							Name:    "GetConfig",
							Package: "pkg/core",
							CalledBy: []string{
								"pkg/a.F1", "pkg/a.F2",
								"pkg/b.F1", "pkg/b.F2",
								"pkg/c.F1", "pkg/c.F2",
							},
						},
					},
				},
				{Path: "pkg/a", Functions: []domain.Function{{Name: "F1", Package: "pkg/a"}, {Name: "F2", Package: "pkg/a"}}},
				{Path: "pkg/b", Functions: []domain.Function{{Name: "F1", Package: "pkg/b"}, {Name: "F2", Package: "pkg/b"}}},
				{Path: "pkg/c", Functions: []domain.Function{{Name: "F1", Package: "pkg/c"}, {Name: "F2", Package: "pkg/c"}}},
			},
			1,
		},
		{
			"few callers same package",
			[]domain.Package{
				{
					Path: "pkg/core",
					Functions: []domain.Function{
						{
							Name:     "Helper",
							Package:  "pkg/core",
							CalledBy: []string{"pkg/core.A", "pkg/core.B"},
						},
					},
				},
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &CodeSmellDetector{}
			issues := d.detectShotgunSurgery(tt.pkgs)
			if len(issues) < tt.wantMin {
				t.Errorf("detectShotgunSurgery() returned %d issues, want at least %d", len(issues), tt.wantMin)
			}
		})
	}
}

func TestGodPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkgs    []domain.Package
		wantMin int
	}{
		{
			"high coupling low abstractness",
			func() []domain.Package {
				godPkg := domain.Package{
					Path:    "pkg/god",
					Imports: []string{"pkg/d1", "pkg/d2", "pkg/d3", "pkg/d4", "pkg/d5"},
					Types:   []domain.Type{{Name: "Concrete1", Kind: "struct"}, {Name: "Concrete2", Kind: "struct"}},
				}
				var fns []domain.Function
				for i := 0; i < 10; i++ {
					fns = append(fns, domain.Function{
						Name:    "Fn",
						Package: "pkg/god",
						CalledBy: []string{
							"pkg/c1.X", "pkg/c2.X", "pkg/c3.X", "pkg/c4.X", "pkg/c5.X",
						},
					})
				}
				godPkg.Functions = fns

				pkgs := []domain.Package{godPkg}
				for _, name := range []string{"pkg/d1", "pkg/d2", "pkg/d3", "pkg/d4", "pkg/d5", "pkg/c1", "pkg/c2", "pkg/c3", "pkg/c4", "pkg/c5"} {
					pkgs = append(pkgs, domain.Package{
						Path:      name,
						Functions: []domain.Function{{Name: "X", Package: name}},
					})
				}
				return pkgs
			}(),
			1,
		},
		{
			"small isolated package",
			[]domain.Package{
				{
					Path:      "pkg/small",
					Functions: []domain.Function{{Name: "Do", Package: "pkg/small"}},
					Types:     []domain.Type{{Name: "Svc", Kind: "struct"}},
				},
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &CodeSmellDetector{}
			issues := d.detectGodPackage(tt.pkgs)
			if len(issues) < tt.wantMin {
				t.Errorf("detectGodPackage() returned %d issues, want at least %d", len(issues), tt.wantMin)
			}
		})
	}
}

func TestExtractPkgFromQualified(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pkg/a.Func", "pkg/a"},
		{"Func", ""},
		{"a.b.c.Func", "a.b.c"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractPkgFromQualified(tt.input)
			if got != tt.want {
				t.Errorf("extractPkgFromQualified(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
