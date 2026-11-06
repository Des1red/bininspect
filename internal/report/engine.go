package report

import (
	"fmt"
	"os"

	"bininspect/internal/models"
)

func Engine() {
	initStyle()

	reportOutput = os.Stdout
	fullReport = false

	r := models.Results

	// Colored, summarized terminal report.
	render(r)

	// Complete, uncolored Markdown report.
	filename, err := saveReport(models.Scope.Target, r)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"BinInspect: saving report failed: %v\n",
			err,
		)
		return
	}

	fmt.Printf("Report saved: %s\n", filename)
}

func render(r models.ResultsModel) {
	header("BININSPECT / STATIC BINARY ANALYSIS")

	emitf("Target: %s\n", models.Scope.Target)
	emitf("Format: %s\n", r.Identity.Format)

	Overview(r)
	Security(r)
	Findings(r)

	emitln()
	emitln(paint(green, "Analysis complete."))
}
