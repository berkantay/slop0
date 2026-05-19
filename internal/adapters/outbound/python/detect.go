package python

import (
	"os"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"__pycache__": true, ".venv": true, "venv": true,
	"dist": true, "build": true,
}

func shouldSkipDir(name string) bool {
	return skipDirs[name] || strings.HasPrefix(name, ".")
}

func DetectLanguage(dir string) string {
	counts := countFilesByLang(dir)
	best := pickBestLang(counts)
	if best == "" {
		return detectByMarkerFiles(dir)
	}
	return best
}

func countFilesByLang(dir string) map[string]int {
	counts := map[string]int{"go": 0, "python": 0, "typescript": 0}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go":
			counts["go"]++
		case ".py":
			counts["python"]++
		case ".ts", ".tsx":
			if !strings.HasSuffix(path, ".d.ts") {
				counts["typescript"]++
			}
		}
		return nil
	})
	return counts
}

func pickBestLang(counts map[string]int) string {
	best := ""
	bestCount := 0
	for lang, count := range counts {
		if count > bestCount {
			bestCount = count
			best = lang
		}
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
			if shouldSkipDir(name) {
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
