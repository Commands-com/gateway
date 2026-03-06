package httputil

import (
	"testing"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Basic abc123", ""},
		{"Bearer tok123", "tok123"},
		{"bearer tok123", "tok123"},
		{"BEARER tok123", "tok123"},
		{"  Bearer   tok123  ", "tok123"},
		{"Bearer ", ""},
	}
	for _, tt := range tests {
		got := BearerToken(tt.header)
		if got != tt.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestRandomTokenLength(t *testing.T) {
	tok, err := RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestRandomTokenUniqueness(t *testing.T) {
	a, _ := RandomToken(32)
	b, _ := RandomToken(32)
	if a == b {
		t.Fatal("expected different tokens")
	}
}
