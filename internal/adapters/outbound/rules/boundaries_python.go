package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type PythonBoundaryDetector struct{}

var pythonBoundaryRules = []struct {
	kind     string
	packages []string
}{
	{"database", []string{
		"sqlalchemy", "psycopg2", "psycopg", "asyncpg", "databases",
		"django.db", "tortoise", "peewee", "pymongo", "motor",
		"aiosqlite", "sqlite3",
	}},
	{"cache", []string{
		"redis", "aioredis", "memcache", "pymemcache", "diskcache",
	}},
	{"message-queue", []string{
		"pika", "aiokafka", "confluent_kafka", "kombu",
		"aio_pika", "nats",
	}},
	{"task-queue", []string{
		"celery", "dramatiq", "huey", "rq", "arq",
	}},
	{"object-storage", []string{
		"boto3", "minio", "google.cloud.storage",
	}},
	{"http-client", []string{
		"httpx", "requests", "aiohttp", "urllib3",
	}},
	{"grpc", []string{
		"grpc", "grpcio",
	}},
}

func (d *PythonBoundaryDetector) Detect(pkgs []domain.Package) []domain.ExternalDep {
	seen := make(map[string]bool)
	var deps []domain.ExternalDep

	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			classifyPythonImport(imp, pkg.Path, seen, &deps)
		}
	}

	return deps
}

func classifyPythonImport(imp, ownerPkg string, seen map[string]bool, deps *[]domain.ExternalDep) {
	importedModule := extractModuleName(imp)

	for _, rule := range pythonBoundaryRules {
		for _, prefix := range rule.packages {
			if importedModule == prefix || strings.HasPrefix(importedModule, prefix+".") {
				key := rule.kind + ":" + importedModule
				if seen[key] {
					return
				}
				seen[key] = true
				*deps = append(*deps, domain.ExternalDep{
					Kind:    rule.kind,
					Package: importedModule,
					Type:    importedModule,
					UsedBy:  ownerPkg,
				})
				return
			}
		}
	}
}

func extractModuleName(imp string) string {
	imp = strings.TrimSpace(imp)

	if strings.HasPrefix(imp, "from ") {
		parts := strings.Fields(imp)
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	if strings.HasPrefix(imp, "import ") {
		parts := strings.Fields(imp)
		if len(parts) >= 2 {
			mod := parts[1]
			mod = strings.Split(mod, " ")[0]
			mod = strings.TrimRight(mod, ",")
			return mod
		}
	}

	return imp
}
