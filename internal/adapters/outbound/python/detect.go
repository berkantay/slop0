package python

import (
	"os"
	"path/filepath"
	"strings"
)

func DetectLanguage(dir string) string {
	goCount := 0
	pyCount := 0

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" || name == "__pycache__" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go":
			goCount++
		case ".py":
			pyCount++
		}
		return nil
	})

	if goCount > 0 && pyCount == 0 {
		return "go"
	}
	if pyCount > 0 && goCount == 0 {
		return "python"
	}

	if goCount > 0 && pyCount > 0 {
		return detectByMarkerFiles(dir)
	}

	return "go"
}

func detectByMarkerFiles(dir string) string {
	goMarkers := []string{"go.mod", "go.sum"}
	pyMarkers := []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile"}

	goScore := countMarkers(dir, goMarkers)
	pyScore := countMarkers(dir, pyMarkers)

	if pyScore > goScore {
		return "python"
	}
	return "go"
}

func countMarkers(dir string, markers []string) int {
	count := 0
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			count++
		}
	}
	return count
}

func CollectPythonFiles(dir string) ([]string, error) {
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
			if name == "__pycache__" || name == ".venv" || name == "venv" || name == ".git" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".py" {
			files = append(files, path)
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

	rel = strings.TrimSuffix(rel, ".py")
	rel = strings.TrimSuffix(rel, "/__init__")
	return strings.ReplaceAll(rel, string(filepath.Separator), ".")
}
