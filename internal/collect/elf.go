package collect

import (
	"fmt"
	"io"

	"bininspect/internal/analyzer"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

// ELFEngine coordinates parsing, decoding, and analysis.
// The caller owns reader and keeps it open for this call.
func ELFEngine(
	reader io.ReaderAt,
	size uint64,
) (analyzer.Result, error) {
	var result analyzer.Result

	parsed, err := binary.Engine(reader, size)
	if err != nil {
		return result, fmt.Errorf(
			"ELF parsing: %w", err,
		)
	}

	decoded, err := decoder.Engine(parsed)
	if err != nil {
		return result, fmt.Errorf(
			"ELF decoding: %w", err,
		)
	}

	result, err = analyzer.AnalyzeELF(
		parsed, decoded,
	)
	if err != nil {
		return result, fmt.Errorf(
			"ELF analysis: %w", err,
		)
	}

	return result, nil
}
