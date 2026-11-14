package report

import "bininspect/internal/analyzer"

func Findings(_ analyzer.Result) {
	box("06  SECURITY FINDINGS",
		"Not evaluated: vulnerability detection rules have not run.",
		"This is not evidence that the binary is secure.",
	)
}
