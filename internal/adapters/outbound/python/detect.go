package python

import (
	"os"
	"path/filepath"
	"strings"
)

func DetectLanguage(dir string) string {
	goCount := 0
	pyCount := 0
	tsCount := 0

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" || name == "__pycache__" || name == ".venv" || name == "venv" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		switch ext {
		case ".go":
			goCount++
		case ".py":
			pyCount++
		case ".ts", ".tsx":
			if !strings.HasSuffix(path, ".d.ts") {
				tsCount++
			}
		}
		return nil
	})

	counts := map[string]int{"go": goCount, "python": pyCount, "typescript": tsCount}
	best := "go"
	bestCount := 0
	for lang, count := range counts {
		if count > bestCount {
			bestCount = count
			best = lang
		}
	}

	if bestCount == 0 {
		return detectByMarkerFiles(dir)
	}

	return best
}

func detectByMarkerFiles(dir string) string {
	goMarkers := []string{"go.mod", "go.sum"}
	pyMarkers := []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile"}
	tsMarkers := []string{"tsconfig.json", "package.json"}

	scores := map[string]int{
		"go":         countMarkers(dir, goMarkers),
		"python":     countMarkers(dir, pyMarkers),
		"typescript": countMarkers(dir, tsMarkers),
	}

	best := "go"
	bestScore := 0
	for lang, score := range scores {
		if score > bestScore {
			bestScore = score
			best = lang
		}
	}
	return best
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
