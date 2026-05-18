package rules

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type BoundaryDetector struct{}

func (d *BoundaryDetector) Detect(domainPkgs []domain.Package) ([]domain.ExternalDep, error) {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports,
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []domain.ExternalDep

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			scanType(obj.Type(), pkg.PkgPath, seen, &deps)
		}
	}

	return deps, nil
}

func scanType(t types.Type, ownerPkg string, seen map[string]bool, deps *[]domain.ExternalDep) {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		if ptr, ok := t.(*types.Pointer); ok {
			scanType(ptr.Elem(), ownerPkg, seen, deps)
		}
		if named, ok := t.(*types.Named); ok {
			if st, ok := named.Underlying().(*types.Struct); ok {
				scanStructFields(st, ownerPkg, seen, deps)
			}
		}
		return
	}
	scanStructFields(st, ownerPkg, seen, deps)
}

func scanStructFields(st *types.Struct, ownerPkg string, seen map[string]bool, deps *[]domain.ExternalDep) {
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		fieldType := field.Type()
		if ptr, ok := fieldType.(*types.Pointer); ok {
			fieldType = ptr.Elem()
		}

		named, ok := fieldType.(*types.Named)
		if !ok {
			continue
		}

		obj := named.Obj()
		if obj.Pkg() == nil {
			continue
		}

		pkgPath := obj.Pkg().Path()
		typeName := obj.Name()
		kind := classifyBoundary(pkgPath, typeName)
		if kind == "" {
			continue
		}

		key := kind + ":" + pkgPath + "." + typeName
		if seen[key] {
			continue
		}
		seen[key] = true

		*deps = append(*deps, domain.ExternalDep{
			Kind:     kind,
			Package:  pkgPath,
			Type:     typeName,
			UsedBy:   ownerPkg,
		})
	}
}

var boundaryRules = []struct {
	kind    string
	prefixes []string
}{
	{"database", []string{
		"database/sql", "github.com/jackc/pgx", "github.com/jackc/pgconn",
		"go.mongodb.org/mongo-driver", "github.com/go-sql-driver",
		"gorm.io/gorm", "github.com/jmoiron/sqlx",
		"github.com/uptrace/bun",
	}},
	{"cache", []string{
		"github.com/go-redis", "github.com/redis/go-redis",
		"github.com/bradfitz/gomemcache",
	}},
	{"message-queue", []string{
		"github.com/nats-io/nats", "github.com/IBM/sarama",
		"github.com/segmentio/kafka", "github.com/rabbitmq",
		"github.com/streadway/amqp", "github.com/rabbitmq/amqp091-go",
	}},
	{"object-storage", []string{
		"github.com/aws/aws-sdk-go", "github.com/minio/minio-go",
		"cloud.google.com/go/storage",
	}},
	{"grpc", []string{"google.golang.org/grpc"}},
}

func classifyBoundary(pkgPath, typeName string) string {
	for _, rule := range boundaryRules {
		if matchesAnyPrefix(pkgPath, rule.prefixes) {
			return rule.kind
		}
	}

	if pkgPath == "net/http" && typeName == "Client" {
		return "http-client"
	}

	return ""
}

func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
