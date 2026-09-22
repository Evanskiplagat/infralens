package cli

import (
	"testing"

	"infralens/internal/findings"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  findings.Severity
	}{
		{"info", findings.SeverityInfo},
		{"low", findings.SeverityLow},
		{"medium", findings.SeverityMedium},
		{"high", findings.SeverityHigh},
		{"critical", findings.SeverityCritical},
	}

	for _, tt := range tests {
		got, err := parseSeverity(tt.input)
		if err != nil {
			t.Fatalf("parseSeverity(%q) returned error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("parseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseSeverityRejectsUnknownValues(t *testing.T) {
	if _, err := parseSeverity("urgent"); err == nil {
		t.Fatal("parseSeverity should reject unknown values")
	}
}

func TestShouldFailOnFindings(t *testing.T) {
	found := []findings.Finding{
		{Severity: findings.SeverityLow},
		{Severity: findings.SeverityHigh},
	}

	if shouldFailOnFindings(found, "") {
		t.Fatal("empty fail-on severity should not fail")
	}
	if !shouldFailOnFindings(found, findings.SeverityHigh) {
		t.Fatal("high-severity finding should trigger fail-on high")
	}
	if shouldFailOnFindings(found[:1], findings.SeverityHigh) {
		t.Fatal("low-severity finding should not trigger fail-on high")
	}
	if shouldFailOnFindings(found, findings.SeverityCritical) {
		t.Fatal("a high finding should not trigger fail-on critical")
	}
	found = append(found, findings.Finding{Severity: findings.SeverityCritical})
	if !shouldFailOnFindings(found, findings.SeverityCritical) {
		t.Fatal("a critical finding should trigger fail-on critical")
	}
}
