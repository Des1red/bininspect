package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"bininspect/internal/models"
)

var (
	reportOutput io.Writer = os.Stdout
	fullReport   bool
)

func emitf(format string, args ...any) {
	_, _ = fmt.Fprintf(reportOutput, format, args...)
}

func emitln(args ...any) {
	_, _ = fmt.Fprintln(reportOutput, args...)
}

func reportFilename(target string) string {
	return filepath.Base(filepath.Clean(target)) +
		"_bininspect.md"
}

func reportText(value string, limit int) string {
	if fullReport {
		return value
	}

	return short(value, limit)
}

func saveReport(
	target string,
	results models.ResultsModel,
) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("empty binary target")
	}

	base := filepath.Base(filepath.Clean(target))
	if base == "." || base == string(filepath.Separator) {
		return "", fmt.Errorf("invalid binary target %q", target)
	}

	var buffer bytes.Buffer

	oldOutput := reportOutput
	oldColors := colors
	oldFull := fullReport

	func() {
		defer func() {
			reportOutput = oldOutput
			colors = oldColors
			fullReport = oldFull
		}()

		reportOutput = &buffer
		colors = false
		fullReport = true

		render(results)
	}()

	filename := reportFilename(target)

	content := "# BinInspect Report\n\n````text\n" +
		strings.TrimRight(buffer.String(), "\n") +
		"\n````\n"

	if err := os.WriteFile(
		filename,
		[]byte(content),
		0644,
	); err != nil {
		return "", err
	}

	return filename, nil
}
