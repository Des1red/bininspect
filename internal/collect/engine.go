package collect

import (
	"fmt"
	"os"

	"bininspect/internal/analyzer"
)

// Engine runs the collection and analysis pipeline
// for an ELF target.
func Engine(path string) (analyzer.Result, error) {
	var result analyzer.Result

	if path == "" {
		return result, fmt.Errorf("empty binary target")
	}

	file, err := os.Open(path)
	if err != nil {
		return result, fmt.Errorf(
			"opening target %q: %w", path, err,
		)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return result, fmt.Errorf(
			"stat target %q: %w", path, err,
		)
	}

	if !info.Mode().IsRegular() {
		return result, fmt.Errorf(
			"target %q is not a regular file", path,
		)
	}

	return ELFEngine(file, uint64(info.Size()))
}
