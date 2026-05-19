package typescript

import (
	"os"
	"path/filepath"
	"strings"
)

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
			if name == "node_modules" || name == "dist" || name == "build" || name == ".next" || name == "coverage" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext == ".ts" || ext == ".tsx" {
			if !strings.HasSuffix(path, ".d.ts") {
				files = append(files, path)
			}
		}
		return nil
	})
	return files, err
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
