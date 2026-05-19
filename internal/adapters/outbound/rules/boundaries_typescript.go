package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type TypeScriptBoundaryDetector struct{}

var tsBoundaryRules = []struct {
	kind     string
	packages []string
}{
	{"database", []string{
		"prisma", "@prisma/client", "typeorm", "sequelize", "knex",
		"mongoose", "mongodb", "pg", "mysql2", "better-sqlite3",
		"drizzle-orm", "mikro-orm",
	}},
	{"cache", []string{
		"ioredis", "redis", "node-cache", "keyv", "catbox",
	}},
	{"message-queue", []string{
		"kafkajs", "amqplib", "bullmq", "bull", "nats",
		"@google-cloud/pubsub", "sqs-consumer",
	}},
	{"object-storage", []string{
		"@aws-sdk/client-s3", "aws-sdk", "minio",
		"@google-cloud/storage", "@azure/storage-blob",
	}},
	{"http-client", []string{
		"axios", "node-fetch", "got", "undici", "ky",
	}},
	{"grpc", []string{
		"@grpc/grpc-js", "@grpc/proto-loader", "grpc",
	}},
	{"graphql", []string{
		"@apollo/server", "@apollo/client", "graphql",
		"type-graphql", "nexus", "pothos",
	}},
}

func (d *TypeScriptBoundaryDetector) Detect(pkgs []domain.Package) []domain.ExternalDep {
	seen := make(map[string]bool)
	var deps []domain.ExternalDep

	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			classifyTSImport(imp, pkg.Path, seen, &deps)
		}
	}

	return deps
}

func classifyTSImport(imp, ownerPkg string, seen map[string]bool, deps *[]domain.ExternalDep) {
	moduleName := extractTSModuleName(imp)

	for _, rule := range tsBoundaryRules {
		for _, prefix := range rule.packages {
			if moduleName == prefix || strings.HasPrefix(moduleName, prefix+"/") {
				key := rule.kind + ":" + moduleName
				if seen[key] {
					return
				}
				seen[key] = true
				*deps = append(*deps, domain.ExternalDep{
					Kind:    rule.kind,
					Package: moduleName,
					Type:    moduleName,
					UsedBy:  ownerPkg,
				})
				return
			}
		}
	}
}

func extractTSModuleName(imp string) string {
	imp = strings.TrimSpace(imp)

	for _, q := range []string{`"`, `'`} {
		start := strings.LastIndex(imp, q)
		if start < 0 {
			continue
		}
		rest := imp[:start]
		prevQ := strings.LastIndex(rest, q)
		if prevQ >= 0 {
			return rest[prevQ+1:]
		}
	}

	if strings.Contains(imp, "from") {
		parts := strings.Split(imp, "from")
		if len(parts) >= 2 {
			mod := strings.TrimSpace(parts[len(parts)-1])
			mod = strings.Trim(mod, `"';`)
			return mod
		}
	}

	return imp
}
