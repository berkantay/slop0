package rules

import (
	"testing"
)

func TestDetectHardcodedSecrets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"clean env var", `x := os.Getenv("API_KEY")`, 0},
		{"hardcoded api key", `apiKey = "sk-1234567890abcdef"`, 1},
		{"placeholder", `apiKey = "your_api_key_here"`, 0},
		{"github token", `token := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`, 2},
		{"high entropy string", `token := "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3"`, 1},
		{"hardcoded password", `password = "SuperSecret123!"`, 1},
		{"secret key assignment", `secret_key = "abcdefghijklmnop"`, 1},
		{"bearer token", `header := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"`, 1},
		{"empty string", `apiKey = ""`, 0},
		{"test placeholder", `password = "changeme"`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectHardcodedSecrets([]byte(tt.input), "app.go", "pkg/app")
			if len(got) != tt.wantLen {
				t.Errorf("detectHardcodedSecrets(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestDetectHardcodedSecretsSkipsTestFiles(t *testing.T) {
	input := `apiKey = "sk-1234567890abcdef"`
	got := detectHardcodedSecrets([]byte(input), "app_test.go", "pkg/app")
	if len(got) != 0 {
		t.Errorf("detectHardcodedSecrets should skip test files, got %d issues", len(got))
	}
}

func TestDetectSQLInjection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"safe parameterized", `db.Query("SELECT * FROM users WHERE id = $1", id)`, 0},
		{"unsafe concatenation", `db.Query("SELECT * FROM users WHERE id = " + id)`, 1},
		{"unsafe f-string", `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`, 1},
		{"safe prepared statement", `stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")`, 0},
		{"unsafe template literal", "db.query(`SELECT * FROM users WHERE id = ${id}`)", 1},
		{"unsafe format string", `db.execute("SELECT * FROM users WHERE id = %s" % user_id)`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSQLInjection([]byte(tt.input), "db.go", "pkg/db")
			if len(got) != tt.wantLen {
				t.Errorf("detectSQLInjection(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestDetectCommandInjection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"safe exec", `cmd := exec.Command("ls", "-la")`, 0},
		{"unsafe subprocess call", `subprocess.call(user_input)`, 1},
		{"unsafe os.system", `os.system(cmd)`, 1},
		{"shell=True", `subprocess.Popen(cmd, shell=True)`, 1},
		{"child_process.exec", `child_process.exec(userInput)`, 1},
		{"safe string literal", `fmt.Println("hello world")`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectCommandInjection([]byte(tt.input), "run.go", "pkg/run")
			if len(got) != tt.wantLen {
				t.Errorf("detectCommandInjection(%q) returned %d issues, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestIsLikelyPlaceholder(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`apiKey = "your_api_key_here"`, true},
		{`apiKey = "sk-real-secret-key"`, false},
		{`password = "changeme"`, true},
		{`token = "placeholder_token"`, true},
		{`key = "AKIAIOSFODNN7EXAMPLE"`, true},
		{`secret = "dummy_value"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isLikelyPlaceholder(tt.input)
			if got != tt.want {
				t.Errorf("isLikelyPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		input string
		low  float64
		high float64
	}{
		{"empty", "", 0, 0.01},
		{"single char", "aaaa", 0, 0.01},
		{"random-looking", "aB3$xZ9!kL2@mN5", 3.5, 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.low || got > tt.high {
				t.Errorf("shannonEntropy(%q) = %f, want between %f and %f", tt.input, got, tt.low, tt.high)
			}
		})
	}
}
