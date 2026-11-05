package internal

import (
	"fmt"

	"bininspect/internal/analyzer"
	"bininspect/internal/collect"
	"bininspect/internal/report"
)

func Inspect() {
	activateEngine()

	if err := collect.Engine(); err != nil {
		fmt.Println("collection error:", err)
		return
	}

	analyzer.Engine()
	report.Engine()
}
