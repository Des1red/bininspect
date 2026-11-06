package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"bininspect/internal/models"
)

func TestReportFilename(t *testing.T) {
	targets := []string{
		"bin",
		"ex00/bin",
		"/home/kali/hole-files/ex01/bin",
	}

	for _, target := range targets {
		got := reportFilename(target)

		if got != "bin_bininspect.md" {
			t.Fatalf("unexpected filename: %s", got)
		}
	}
}

func TestFullReport(t *testing.T) {
	var result models.ResultsModel

	result.Identity.Format = "ELF"

	for i := 0; i < 12; i++ {
		result.Findings = append(
			result.Findings,
			models.Finding{
				ID:       fmt.Sprintf("TEST-%02d", i+1),
				Severity: "low",
			},
		)
	}

	for i := 0; i < 7; i++ {
		result.Structure.Libraries = append(
			result.Structure.Libraries,
			fmt.Sprintf("library-%02d.so", i+1),
		)
	}

	var buffer bytes.Buffer

	oldOutput := reportOutput
	oldColors := colors
	oldFull := fullReport

	defer func() {
		reportOutput = oldOutput
		colors = oldColors
		fullReport = oldFull
	}()

	reportOutput = &buffer
	colors = false
	fullReport = true

	render(result)

	output := buffer.String()

	if !strings.Contains(output, "FINDING 12") {
		t.Fatal("full report omitted findings")
	}

	if !strings.Contains(output, "library-07.so") {
		t.Fatal("full report omitted dependencies")
	}

	if strings.Contains(output, "... and ") ||
		strings.Contains(output, "additional findings omitted") {
		t.Fatal("full report contains truncation messages")
	}

	if strings.Contains(output, "\033[") {
		t.Fatal("full report contains ANSI colors")
	}
}
