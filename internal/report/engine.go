package report

import (
	"fmt"

	"bininspect/internal/models"
)

func Engine() {
	initStyle()

	r := models.Results

	header("BININSPECT / STATIC BINARY ANALYSIS")

	fmt.Printf("Target: %s\n", models.Scope.Target)
	fmt.Printf("Format: %s\n", r.Identity.Format)

	Overview(r)
	Security(r)
	Findings(r)

	fmt.Println()
	fmt.Println(paint(green, "Analysis complete."))
}
