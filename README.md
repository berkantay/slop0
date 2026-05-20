<p align="center">
  <h1 align="center">slop0</h1>
  <p align="center">Deterministic code quality rubric for LLM-generated code</p>
  <p align="center">
    <a href="#installation">Installation</a> |
    <a href="#quick-start">Quick Start</a> |
    <a href="#philosophy">Philosophy</a> |
    <a href="#what-it-detects">What It Detects</a> |
    <a href="#graph-algorithms">Graph Algorithms</a> |
    <a href="#for-sft">For SFT</a>
  </p>
</p>

---

**slop0** analyzes codebases and outputs a structured quality report using graph algorithms, AST analysis, and Bayesian confidence scoring.

Built to score LLM-generated code for supervised fine-tuning. One command gives you the full picture — structure, violations, design patterns, graph positions, coupling metrics, and code smells.

```
$ slop0 ./
=== SUMMARY ===
142 packages, 1104 functions, 739 types
total:739 external-dep:45 implements:89 low-cohesion:12
entry: 92 http routes
deps: database (Pool) | cache (Client) | http-client (Client)
findings: 633 issues, 347 patterns
hotspots: service.ProcessOrder (rank:0.042 blast:47)
```

## Philosophy

### No architecture assumptions

slop0 does not assume hexagonal, MVC, clean architecture, or any pattern. It reports what the graph IS — not what it thinks your architecture SHOULD be.

A type with `in:12 out:0 fields:8` is a fact. Calling it "domain entity" or "model" or "data-holder" is an interpretation that depends on your architecture. slop0 doesn't interpret — it measures.

### Detection hierarchy

```
1. Graph algorithms      — Brandes, Tarjan, Louvain, DSM (pure math)
2. Type-based analysis   — resolved types via LSP, not name matching
3. AST structural checks — tree-sitter node types, not regex
4. Signature analysis    — function shapes, not function names
5. Regex (last resort)   — only for secrets, entropy, string patterns
```

Each level is more precise than the next. slop0 prefers graph math over pattern matching, type resolution over name matching, and structural detection over string searching.

### No hardcoded framework lists

Route detection doesn't check "is this chi/gin/echo". It checks: does this function take a string starting with "/" and a handler function? That works for any HTTP framework.

Barrel import detection doesn't check "is this lodash". It checks: does this import pull >5 named exports from a single non-relative module? That works for any large package.

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
# Go — enables precise call graph, interface resolution
go install golang.org/x/tools/gopls@latest

# Python — enables type inference, cross-file references
npm install -g pyright

# TypeScript — enables type resolution, call hierarchy
npm install -g typescript-language-server typescript
```

## Quick Start

```bash
# Auto-detects language from file extensions
slop0

# Force language
slop0 --lang=python ./my-project
slop0 --lang=typescript ./my-app

# Only violations (skip structure output)
slop0 --rules-only

# JSON for pipelines
slop0 --format=json

# Focus on a symbol and its N-depth neighbors
slop0 --focus=ProcessOrder --depth=3
```

## What It Detects

### 130+ rules across 3 languages and 4 frameworks

| Category | Rules | Detection Method |
|----------|-------|-----------------|
| **Go** | 31 | `go/packages` + `go/ssa` + gopls LSP |
| **Python** | 13 | tree-sitter + pyright LSP |
| **TypeScript** | 8 | tree-sitter AST nodes (not regex) |
| **React** | 11 | tree-sitter JSX analysis |
| **Next.js** | 14 | AST + file convention analysis |
| **Django** | 7 | AST + ORM pattern analysis |
| **FastAPI** | 6 | AST + decorator analysis |
| **Security** | 8 | Shannon entropy + AST argument analysis |
| **Code quality** | 9 | Cross-language AST patterns |
| **Code smells** | 10 | Graph algorithms on call/import graph |

### Security (OWASP-aligned)

| Rule | Detection |
|------|-----------|
| Hardcoded secrets | Shannon entropy > 4.5 + known token format patterns |
| SQL injection | Dynamic string (not literal) in query call arguments |
| Command injection | Non-literal args in exec/subprocess calls |
| XSS | `dangerouslySetInnerHTML` AST node, `innerHTML` assignment |
| Insecure deserialization | `eval()`, `pickle.loads`, `yaml.load` without SafeLoader |
| CORS wildcard | `allow_origins=["*"]` |

### React

| Rule | Detection |
|------|-----------|
| useEffect for derived state | Effect body only calls setState with props/state values |
| useEffect chains | Effect sets state that appears in another effect's dependency array |
| Inline functions in JSX | Arrow function or .bind() as JSX attribute value |
| Index as key | `.map()` callback JSX key prop uses second parameter |
| Missing query invalidation | `useMutation` without `invalidateQueries` in callbacks |
| God component | >50 JSX elements or >8 hook calls |
| Too many useState | 5+ useState calls → suggest useReducer |

### Next.js (from production checklist)

| Rule | Detection |
|------|-----------|
| Unnecessary "use client" | Directive present but no hooks, events, or browser APIs in AST |
| Missing error.tsx | Route directory has page but no error boundary |
| Missing loading.tsx | Async route without loading UI |
| Missing metadata | Page file without metadata/generateMetadata export |
| Missing Suspense | Async server component without Suspense boundary |
| Missing generateStaticParams | Dynamic route `[slug]` without static generation |
| Server action no validation | "use server" function receives FormData without schema parsing |
| Server fetching own API | Server component calling own `/api/` route (unnecessary roundtrip) |
| Dynamic in root layout | `cookies()`/`headers()` in root layout opts entire app dynamic |

### Code Smells (graph-derived)

| Smell | Detection |
|-------|-----------|
| Feature envy | Function calls another package more than its own (≥3 foreign calls) |
| Shotgun surgery | Function has >5 callers across ≥3 packages |
| Middle man | Function with 1 callee and 2+ callers, crossing package boundary |
| Data clumps | Same 3+ parameter types in 4+ function signatures |
| God package | High afferent + high efferent coupling + low abstractness |
| N+1 pattern | Async/DB call inside loop body (any language) |
| Dead exports | Exported function/type never imported |
| Duplicated types | Same field names in types across different packages |
| Prop drilling | React prop passed to child without being used in component |
| Route without error handling | API route handler with no try-catch |

### Design Patterns Detected

| Pattern | Structural Signal |
|---------|------------------|
| Interface boundary | Interface in package A, implementation in package B |
| Strategy | Interface with 2+ implementations across packages |
| Middleware | Function signature `func(X) X` — same input and output type |
| Decorator | Struct holds and implements same interface |
| Factory | Function returns interface type (hides concrete) |
| Builder | 3+ chainable methods returning `*self` |
| Singleton | `sync.Once` at package level (detected by type, not name) |

## Graph Algorithms

Six algorithms run on the call graph and import graph. Pure math — no name matching, no architecture assumptions.

### Brandes Betweenness Centrality `O(VE)`

Finds bottleneck functions that sit on most shortest paths between all pairs. Functions with betweenness > mean + 2σ are flagged. Unlike PageRank (finds what's heavily depended on), betweenness finds intermediaries — the gateway functions connecting different parts of the system.

### Tarjan Strongly Connected Components `O(V+E)`

Finds circular dependency clusters in the call graph. Not just import cycles — mutual call dependencies. Suggests which edge to cut (greedy: highest internal out-degree).

### Topological Layer Assignment `O(V+E)`

Auto-detects layers from the DAG without looking at names:
- **Layer 0**: Nodes with no dependencies
- **Layer N**: Depends on layers 0..N-1

Layer skip violation: edge from layer L to layer L+2+. Detects architectural violations purely from dependency direction.

### Louvain Community Detection `O(n log n)`

Finds natural module boundaries by maximizing modularity Q. Detects misplaced code: function F is in package A but its graph community is package B (more edges to B than A).

### Henry-Kafura Information Flow

```
IF(f) = length(f) × (fan_in × fan_out)²
```

Flags functions with IF > 1000 — structurally complex regardless of line count. A 5-line function called by 10 things and calling 10 things has IF = 50,000.

### Dependency Structure Matrix

Square matrix of package dependencies, topologically sorted. Entries above the diagonal are back-edges — dependency direction violations. The most compact representation of an entire codebase's architecture.

## Type Graph Positions

Every type is described by its position in the graph — not classified into roles:

```
=== TYPE GRAPH POSITIONS ===
  domain.Package    in:15 out:0 fields:5 methods:0
  domain.Report     in:4  out:0 fields:8 methods:0
  rules.Engine      in:0  out:15 fields:12 methods:1 impl:2 ext-dep LCOM4=9
  golang.Resolver   in:0  out:16 fields:2 methods:5 impl:1 ext-dep LCOM4=2
```

A type with `in:15 out:0 fields:5` is a structural fact. Whether you call it a "domain entity", "model", or "data holder" depends on your architecture — slop0 doesn't assume.

## Package Metrics

Robert Martin's metrics for every package:

| Metric | Formula | Meaning |
|--------|---------|---------|
| Ca | afferent coupling | Who depends on me |
| Ce | efferent coupling | Who do I depend on |
| I | Ce / (Ca + Ce) | Instability (0=stable, 1=unstable) |
| A | interfaces / types | Abstractness |
| D | \|A + I - 1\| | Distance from main sequence (0=ideal) |

## Confidence Scoring

Every finding has a confidence score via **Bayesian noisy-OR fusion**:

```
P(real) = 1 - ∏(1 - signal_i)
```

Multiple independent signals combine. Example for interface-boundary pattern:
- Cross-package boundary: +0.3
- Type used AS the interface somewhere: +0.4
- Interface has 2+ methods: +0.25
- Combined: 0.685 → medium confidence

Labels: `[high]` ≥ 0.8, `[medium]` ≥ 0.5, `[low]` < 0.5.

## For SFT

slop0 is a scoring rubric for supervised fine-tuning of code generation models.

**Workflow:**
1. Give a coding task to your model
2. Model generates code
3. Run `slop0 --format=json` on the output
4. Use findings to score quality
5. Filter training data: keep low-violation outputs, discard slop

**What makes it work for SFT:**
- **Deterministic** — same input, same output, always
- **Structural** — graph math over pattern matching
- **Architecture-agnostic** — no hexagonal/MVC/clean architecture bias
- **Confidence-scored** — not all findings are equal weight
- **Self-consistent** — slop0 passes its own 130+ rules with zero violations

## Configuration

```bash
slop0 init  # generates .slop0.yaml template
```

```yaml
thresholds:
  max_params: 5
  max_returns: 2
  max_methods_per_type: 15
  func_max_lines: 60
  max_cognitive_complexity: 15
  max_cyclomatic_complexity: 10
  max_map_literal_keys: 3
  dup_ast_min_nodes: 25
  dup_similarity: 0.7

layers:  # optional, for explicit layer rules
  - name: core
    packages: ["./internal/domain/..."]
    allowed_deps: []
  - name: application
    packages: ["./internal/app/..."]
    allowed_deps: ["core"]
```

## Architecture

```
cmd/slop0/main.go                     ← composition root
internal/
├── domain/                            ← pure types, no deps
├── application/
│   ├── ports/{inbound,outbound}/      ← interfaces
│   └── usecases/                      ← orchestration
└── adapters/outbound/
    ├── golang/                        ← Go: go/packages + go/ssa
    ├── python/                        ← Python: tree-sitter
    ├── typescript/                    ← TypeScript: tree-sitter
    ├── lsp/                           ← LSP JSON-RPC client
    ├── rules/                         ← 130+ detectors + 6 graph algorithms
    ├── renderer/                      ← compact text + JSON
    └── config/                        ← .slop0.yaml loader
```

## License

MIT
