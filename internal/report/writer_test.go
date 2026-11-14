package report

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
	"testing"

	"bininspect/internal/analyzer"
	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
)

func TestReportFilename(t *testing.T) {
	for _, target := range []string{
		"bin",
		"ex00/bin",
		"/home/kali/hole-files/ex01/bin",
	} {
		if got := reportFilename(target); got != "bin_bininspect.md" {
			t.Fatalf("unexpected filename: %s", got)
		}
	}
}

func TestFullReport(t *testing.T) {
	result := analyzer.Result{
		Info: binary.Info{
			Format: binary.FormatELF,
			Bits:   64,
		},
		ELFType: elf.ET_EXEC,
		Structure: analyzer.Structure{
			Sections: 7,
		},
	}

	for i := 0; i < 12; i++ {
		result.Graphs = append(
			result.Graphs,
			cfg.Graph{
				Section: i,
				Name:    fmt.Sprintf("section-%02d", i),
			},
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

	render("bin", result)

	output := buffer.String()

	if !strings.Contains(output, "section-11") ||
		!strings.Contains(output, "SECURITY FINDINGS") {
		t.Fatal("full report omitted regions or status")
	}

	if strings.Contains(output, "... additional regions") {
		t.Fatal("full report contains truncation message")
	}

	if strings.Contains(output, "\033[") {
		t.Fatal("full report contains ANSI colors")
	}

	if !strings.Contains(output, "Not evaluated") {
		t.Fatal("report falsely implies security evaluation occurred")
	}
}
