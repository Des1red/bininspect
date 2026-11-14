package report

import "bininspect/internal/analyzer"

func Security(_ analyzer.Result) {
	box("05  SECURITY PROTECTIONS",
		"Not evaluated: NX, PIE, RELRO, stack canary and other hardening checks",
		"will be assessed in the security-analysis stage.",
	)
}
