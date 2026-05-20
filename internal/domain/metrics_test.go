package domain

import (
	"math"
	"testing"
)

func TestNoisyOR(t *testing.T) {
	tests := []struct {
		name    string
		signals []float64
		want    float64
	}{
		{"single 0.5", []float64{0.5}, 0.5},
		{"two 0.5s", []float64{0.5, 0.5}, 0.75},
		{"zero signal", []float64{0.0}, 0.0},
		{"certainty", []float64{1.0}, 1.0},
		{"three 0.3s", []float64{0.3, 0.3, 0.3}, 0.657},
		{"empty", []float64{}, 0.0},
		{"mixed", []float64{0.1, 0.9}, 0.91},
		{"all zeros", []float64{0.0, 0.0, 0.0}, 0.0},
		{"all ones", []float64{1.0, 1.0}, 1.0},
		{"negative clamped", []float64{-0.5}, 0.0},
		{"over one clamped", []float64{1.5}, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NoisyOR(tt.signals...)
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("NoisyOR(%v) = %f, want %f", tt.signals, got, tt.want)
			}
		})
	}
}

func TestConfidenceLabel(t *testing.T) {
	tests := []struct {
		name string
		conf Confidence
		want string
	}{
		{"high", ConfidenceHigh, "high"},
		{"medium", ConfidenceMedium, "medium"},
		{"low", ConfidenceLow, "low"},
		{"exact 0.8", Confidence(0.8), "high"},
		{"just below 0.5", Confidence(0.49), "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.conf.Label()
			if got != tt.want {
				t.Errorf("Confidence(%f).Label() = %q, want %q", float64(tt.conf), got, tt.want)
			}
		})
	}
}

func TestShortPkgName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com/user/repo/internal/pkg", "internal/pkg"},
		{"pkg/a", "pkg/a"},
		{"single", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ShortPkgName(tt.input)
			if got != tt.want {
				t.Errorf("ShortPkgName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
