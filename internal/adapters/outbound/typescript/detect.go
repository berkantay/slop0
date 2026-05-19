package typescript

import (
	"os"
	"path/filepath"
	"strings"
)

var tsSkipDirs = map[string]bool{
	"node_modules": true, "dist": true, "build": true,
	".next": true, "coverage": true,
}

func shouldSkipTSDir(name string) bool {
	return tsSkipDirs[name] || strings.HasPrefix(name, ".")
}

func CollectTSFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "." || name == dir {
				return nil
			}
			if shouldSkipTSDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if isTSSourceFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isTSSourceFile(path string) bool {
	ext := filepath.Ext(path)
	return (ext == ".ts" || ext == ".tsx") && !strings.HasSuffix(path, ".d.ts")
}

func FileToModulePath(filePath, rootDir string) string {
	rel, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return filePath
	}
	rel = strings.TrimSuffix(rel, ".tsx")
	rel = strings.TrimSuffix(rel, ".ts")
	rel = strings.TrimSuffix(rel, "/index")
	return strings.ReplaceAll(rel, string(filepath.Separator), "/")
}
