package internal

import (
	"fmt"
	"os"

	"bininspect/internal/collect"
	"bininspect/internal/models"
	"bininspect/internal/report"
)

func Inspect() {
	result, err := collect.Engine(models.Scope.Target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "BinInspect:", err)
		return
	}

	if err := report.Engine(models.Scope.Target, result); err != nil {
		fmt.Fprintln(os.Stderr, "BinInspect:", err)
	}
}
