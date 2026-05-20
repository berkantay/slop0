package rules

import (
	"testing"
)

func TestDetectDeadBranches(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"no dead branch", `if x > 0 { return }`, 0},
		{"if true", `if true { return }`, 1},
		{"if false", `if false { return }`, 1},
		{"python True", `if True: pass`, 1},
		{"python False", `if False: pass`, 1},
		{"normal condition", `if len(items) > 0 { process() }`, 0},
		{"ternary-like", `x := true`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectDeadBranches([]byte(tt.input), "app.go", "pkg/app")
			if len(got) != tt.wantLen {
				t.Errorf("detectDeadBranches(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestDetectEmptyCatch(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"empty catch", `try { x() } catch (e) {}`, 1},
		{"catch with handler", `try { x() } catch (e) { log(e) }`, 0},
		{"python except pass", "try:\n    x()\nexcept:\n    pass", 1},
		{"no try catch", `x := doSomething()`, 0},
		{"catch with whitespace only", `try { x() } catch (e) {   }`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectEmptyCatch([]byte(tt.input), "app.go", "pkg/app")
			if len(got) != tt.wantLen {
				t.Errorf("detectEmptyCatch(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestDetectDeepNesting(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"shallow", "func main() {\n\tif true {\n\t\tx()\n\t}\n}", 0},
		{"deeply nested", "func f() {\n\t\t\t\t\t\tx := 1\n}", 1},
		{"flat code", "x := 1\ny := 2\nz := 3", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectDeepNesting([]byte(tt.input), "app.go", "pkg/app")
			if len(got) != tt.wantLen {
				t.Errorf("detectDeepNesting(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestDetectTodoFixme(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"todo comment", "// TODO: fix this later", 1},
		{"fixme comment", "// FIXME: broken", 1},
		{"hack comment", "// HACK: workaround", 1},
		{"no marker", "// this is a normal comment", 0},
		{"todo in code not comment", `name := "TODO"`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectTodoFixme([]byte(tt.input), "app.go", "pkg/app")
			if len(got) != tt.wantLen {
				t.Errorf("detectTodoFixme(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"app_test.go", true},
		{"app.go", false},
		{"test_app.py", true},
		{"app.test.ts", true},
		{"app.spec.js", true},
		{"main.go", false},
		{"app_test.py", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isTestFile(tt.input)
			if got != tt.want {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsComment(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"// go comment", true},
		{"# python comment", true},
		{"/* block comment */", true},
		{"* javadoc line", true},
		{"regular code", false},
		{"  // indented comment", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isComment(tt.input)
			if got != tt.want {
				t.Errorf("isComment(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectMagicNumbers(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		file    string
		wantLen int
	}{
		{"magic number", `timeout := 86400`, "app.go", 1},
		{"allowed http status", `return 200`, "app.go", 0},
		{"constant definition", `const maxRetries = 9999`, "app.go", 0},
		{"test file skipped", `x := 99999`, "app_test.go", 0},
		{"small number", `x := 42`, "app.go", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectMagicNumbers([]byte(tt.input), "app.go", "pkg/app", tt.file)
			if len(got) != tt.wantLen {
				t.Errorf("detectMagicNumbers(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}
