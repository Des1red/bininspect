package report

import (
	"fmt"
	"os"

	"bininspect/internal/analyzer"
)

func Engine(target string, result analyzer.Result) error {
	initStyle()

	reportOutput = os.Stdout
	fullReport = false

	render(target, result)

	filename, err := saveReport(target, result)
	if err != nil {
		return fmt.Errorf(
			"saving BinInspect report: %w",
			err,
		)
	}

	fmt.Printf("Report saved: %s\n", filename)
	return nil
}

func render(target string, result analyzer.Result) {
	header("BININSPECT / STATIC ELF ANALYSIS")

	emitf("Target: %s\n", target)
	emitf("Format: %s\n", result.Info.Format)

	Overview(result)

	emitln()
	emitln(paint(green, "Analysis report complete."))
}
