package report

import (
	"strings"
	"testing"
)

func TestSummaryColors(t *testing.T) {
	previous := colors
	defer func() { colors = previous }()

	input := "ELF32: strcpy() detected; NX disabled; RELRO unknown; 64 bytes."

	risky := map[string]bool{
		"strcpy": true,
	}

	colors = true

	output := colorSummary(input, risky)

	for _, color := range []string{red, blue, yellow} {
		if !strings.Contains(output, color) {
			t.Fatalf("missing color %q", color)
		}
	}

	if stripANSI(output) != input {
		t.Fatal("coloring changed the original text")
	}

	colors = false

	if output := colorSummary(input, risky); output != input {
		t.Fatal("plain report contains formatting changes")
	}
}
