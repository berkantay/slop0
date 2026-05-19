<p align="center">
  <h1 align="center">slop0</h1>
  <p align="center">Deterministic code quality rubric for LLM-generated code</p>
  <p align="center">
    <a href="#installation">Installation</a> |
    <a href="#quick-start">Quick Start</a> |
    <a href="#what-it-detects">What It Detects</a> |
    <a href="#graph-algorithms">Graph Algorithms</a> |
    <a href="#for-sft">For SFT</a>
  </p>
</p>

---

**slop0** analyzes codebases and outputs a structured quality report. It uses graph algorithms, type-based detection, and Bayesian confidence scoring — not string matching or regex heuristics.

Built to score LLM-generated code for supervised fine-tuning (SFT). One command gives you structure, violations, design patterns, architectural layers, and coupling metrics.

```
$ slop0 ./
=== SUMMARY ===
142 packages, 1104 functions, 739 types
entry: 92 http routes
deps: database (Pool) | cache (Client) | http-client (Client) | object-storage (Client)
roles: data-holder:243 orchestrator:26 boundary:36 repository:15 transformer:7
findings: 633 issues, 347 patterns
hotspots: service.ProcessOrder (rank:0.042 blast:47)
```

## Why

Coding agents generate slop. They don't understand architecture, they repeat patterns from training data, and they introduce anti-patterns that pass tests but degrade codebases over time.

**slop0** is a deterministic rubric that catches this. Run it on generated code, get a structured report, use the findings to filter training data or as a reward signal for RLHF/SFT.

## Installation

```bash
go install github.com/berkantay/slop0/cmd/slop0@latest
```

Or build from source:

```bash
git clone https://github.com/berkantay/slop0.git
cd slop0
go build ./cmd/slop0
```

### Optional LSP servers (for cross-reference analysis)

```bash
# Go
go install golang.org/x/tools/gopls@latest

# Python
npm install -g pyright

# TypeScript
npm install -g typescript-language-server typescript
```

## Quick Start

```bash
# Analyze current directory (auto-detects language)
slop0

# Force language
slop0 --lang=python ./my-project
slop0 --lang=typescript ./my-app

# Violations only (skip structure)
slop0 --rules-only

# JSON output for pipelines
slop0 --format=json

# Focus on a specific symbol
slop0 --focus=ProcessOrder --depth=3
```

## What It Detects

### Languages

| Language | Parsing | LSP | Rules |
|----------|---------|-----|-------|
| **Go** | `go/packages` + `go/ssa` | gopls | 28 rules (Effective Go + complexity + architecture) |
| **Python** | tree-sitter | pyright | 13 rules (PEP 8 + extras) |
| **TypeScript** | tree-sitter | tsserver | 8 rules (TS idioms via AST nodes) |

### Frameworks

| Framework | Rules | Examples |
|-----------|-------|---------|
| **React** | 11 | useEffect chains, derived state in effects, inline functions in JSX, index-as-key, missing query invalidation, god components |
| **Next.js** | 10 | unnecessary `"use client"`, missing `error.tsx`/`loading.tsx`/`not-found.tsx`, missing metadata, `<img>` instead of `<Image>`, fetch in useEffect |
| **Django** | 7 | N+1 queries, raw SQL, missing `Meta`/`__str__`, ForeignKey without `on_delete`, hardcoded settings |
| **FastAPI** | 6 | missing `response_model`, async calling sync, raw dict params, hardcoded CORS |

### Security (OWASP-aligned)

| Rule | Detection |
|------|-----------|
| Hardcoded secrets | Regex patterns + Shannon entropy > 4.5 |
| SQL injection | Dynamic string in query call arguments |
| Command injection | Non-literal args in exec/subprocess |
| XSS | `dangerouslySetInnerHTML`, `innerHTML` assignment |
| Insecure deserialization | `eval()`, `pickle.loads`, `yaml.load` without SafeLoader |
| CORS wildcard | `allow_origins=["*"]` |
| NEXT_PUBLIC_ misuse | Secret-like names with public prefix |

### Code Quality

| Category | Rules |
|----------|-------|
| Complexity | Cognitive complexity, cyclomatic complexity, long functions, god types, too many params/returns |
| Naming | PEP 8, Effective Go, TS conventions, redundant getters, stuttering names |
| Testing | Missing test files, empty tests, no assertions |
| Dead code | TODO/FIXME markers, dead branches (`if true`), empty catch blocks |
| Anti-patterns | Magic numbers, deep nesting, untyped map literals, mutable defaults |

### Design Patterns Detected

| Pattern | How |
|---------|-----|
| Interface boundary | Interface in package A, implementation in package B |
| Strategy | Interface with 2+ implementations |
| Middleware | `func(X) X` — same input and output type |
| Decorator | Struct holds and implements same interface |
| Factory | Function returns interface type |
| Builder | 3+ chainable methods returning `*self` |
| Singleton | `sync.Once` at package level |

## Graph Algorithms

slop0 runs six graph algorithms on the call graph and import graph. These are pure math — no name matching, no architecture assumptions.

### Brandes Betweenness Centrality `O(VE)`

Finds bottleneck functions that all call paths pass through. Functions with betweenness > mean + 2*stddev are flagged as single points of failure.

### Tarjan Strongly Connected Components `O(V+E)`

Finds circular dependency clusters. Suggests which edge to cut to break the cycle (greedy: highest internal out-degree).

### Topological Layer Assignment `O(V+E)`

Auto-detects architecture layers from the DAG:
- **Layer 0**: No dependencies (domain, types)
- **Layer N**: Depends on layers 0..N-1

Layer skip violations: edge from layer L to layer L+2 or beyond.

### Louvain Community Detection `O(n log n)`

Finds natural module boundaries by maximizing modularity Q. Detects misplaced code: function F is in package A but its graph community is package B.

### Henry-Kafura Information Flow

```
IF(f) = length(f) × (fan_in × fan_out)²
```

Flags functions with IF > 1000. These are structurally complex regardless of line count.

### Dependency Structure Matrix

Square matrix of package dependencies. Topologically sorted — entries above the diagonal are back-edges (violations).

## Package Metrics

For every package, slop0 computes Robert Martin's metrics:

| Metric | Formula | Meaning |
|--------|---------|---------|
| Ca | afferent coupling | Who depends on me |
| Ce | efferent coupling | Who do I depend on |
| I | Ce / (Ca + Ce) | Instability (0=stable, 1=unstable) |
| A | interfaces / types | Abstractness |
| D | \|A + I - 1\| | Distance from main sequence (0=ideal) |

Packages with D > 0.3 and low A + low I are flagged as **zone of pain** (rigid).

## Type Role Classification

Every struct/class is classified by structural behavior:

| Role | Signal |
|------|--------|
| Data holder | High fan-in, low fan-out, many fields, no interface impl |
| Repository | Implements interfaces, holds external dependency |
| Orchestrator | High fan-out to project types, implements interfaces |
| Boundary | Low fan-in (entry point), holds services as deps |
| Transformer | No fields, low fan-in/out, pure functions |

**LCOM4** (Lack of Cohesion of Methods): connected components in the method-field access graph. LCOM4 > 1 means the type should be split.

## Confidence Scoring

Every finding has a confidence score computed via **Bayesian noisy-OR fusion**:

```
P(real) = 1 - ∏(1 - signal_i)
```

Multiple independent signals combine into a single confidence. Example for interface-boundary pattern:
- Cross-package boundary: +0.3
- Type used AS the interface somewhere: +0.4
- Interface has 2+ methods: +0.25
- Combined: `1 - (0.7 × 0.6 × 0.75) = 0.685` → medium confidence

Findings are labeled `[high]`, `[medium]`, or `[low]`.

## For SFT

slop0 is designed as a scoring rubric for supervised fine-tuning of code generation models.

**Workflow:**
1. Give a coding task to your model
2. Model generates code
3. Run `slop0 --format=json` on the output
4. Use findings to score quality
5. Filter training data: keep low-violation outputs, discard slop

**What makes a good rubric:**
- **Deterministic** — same input always produces same output
- **Structural** — detects by graph/type analysis, not pattern matching
- **Confidence-scored** — not all findings are equal
- **Self-consistent** — slop0 passes its own rules with zero violations

## Configuration

```bash
slop0 init  # generates .slop0.yaml template
```

```yaml
thresholds:
  dup_ast_min_nodes: 25
  dup_callgraph_min_calls: 3
  dup_similarity: 0.7
  max_params: 5
  max_returns: 2
  max_methods_per_type: 15
  func_max_lines: 60
  max_cognitive_complexity: 15
  max_cyclomatic_complexity: 10
  max_map_literal_keys: 3

layers:
  - name: domain
    packages: ["./internal/domain/..."]
    allowed_deps: []
  - name: application
    packages: ["./internal/application/..."]
    allowed_deps: ["domain"]
  - name: adapters
    packages: ["./internal/adapters/..."]
    allowed_deps: ["domain", "application"]
```

## Architecture

slop0 itself follows hexagonal architecture:

```
cmd/slop0/main.go                     ← composition root
internal/
├── domain/                            ← pure types (no deps)
├── application/
│   ├── ports/{inbound,outbound}/      ← interfaces
│   └── usecases/                      ← orchestration
└── adapters/
    ├── inbound/cli/                   ← cobra CLI
    └── outbound/
        ├── golang/                    ← Go analysis (go/packages, go/ssa)
        ├── python/                    ← Python analysis (tree-sitter)
        ├── typescript/                ← TypeScript analysis (tree-sitter)
        ├── lsp/                       ← LSP JSON-RPC client
        ├── rules/                     ← 100+ detectors + graph algorithms
        ├── renderer/                  ← compact text + JSON output
        └── config/                    ← .slop0.yaml loader
```

## License

MIT
