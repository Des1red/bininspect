package internal

import (
	"fmt"
	"os"

	"bininspect/internal/collect"
	"bininspect/internal/models"
)

func Inspect() {
	result, err := collect.Engine(models.Scope.Target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "analysis error:", err)
		return
	}

	fmt.Println("BININSPECT / ELF ANALYSIS")
	fmt.Printf("Target: %s\n", models.Scope.Target)
	fmt.Printf("Format: %s\n", result.Info.Format)
	fmt.Printf("Architecture: %s\n", result.Info.Architecture)
	fmt.Printf("Type: %s\n", result.ELFType)
	fmt.Printf("Sections: %d\n", result.Structure.Sections)
	fmt.Printf("Segments: %d\n", result.Structure.Programs)
	fmt.Printf("Symbols: %d\n", result.Structure.Symbols)
	fmt.Printf("Relocations: %d\n", result.Structure.Relocations)
	fmt.Printf(
		"Instructions: %d\n",
		result.Assembly.CandidateInstructions,
	)
	fmt.Printf("CFG regions: %d\n", len(result.Graphs))
	fmt.Printf(
		"Undecoded bytes: %d\n",
		result.Assembly.SkippedBytes,
	)
}
