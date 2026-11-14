package report

import (
	"fmt"
	"os"

	"bininspect/internal/analyzer"
)

func Engine(target string, r analyzer.Result) error {
	initStyle()
	reportOutput = os.Stdout
	fullReport = false

	render(target, r)

	filename, err := saveReport(target, r)
	if err != nil {
		return fmt.Errorf("saving Markdown report: %w", err)
	}

	emitf("Report saved: %s\n", filename)
	return nil
}

func render(target string, r analyzer.Result) {
	header("BININSPECT / STATIC ELF ANALYSIS")
	emitf("Target: %s\n", target)
	emitf("Format: %s\n", r.Info.Format)

	Overview(r)
	Recovery(r)
	DataFlow(r)
	Security(r)
	Findings(r)
	Summary(r)

	emitln()
	emitln(paint(green, "Analysis complete."))
}
