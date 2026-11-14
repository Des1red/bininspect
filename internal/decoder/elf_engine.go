package decoder

import (
	"errors"
	"fmt"

	"bininspect/internal/binary"
)

// Diagnostic describes a byte range that could not be decoded.
// Section is -1 when using a PT_LOAD fallback.
type Diagnostic struct {
	Section int
	Address uint64
	Size    uint64
	Reason  string
}

// Result contains linear-sweep instruction candidates,
// not recovered functions.
//
// For ET_REL, addresses are section-relative offsets.
type Result struct {
	Sections              []DecodedSection
	Diagnostics           []Diagnostic
	SkippedBytes          uint64
	SkippedDataBytes      uint64
	SuppressedDiagnostics uint64
}

const maxDiagnostics = 1024

func Engine(parsed *binary.ELFResult) (Result, error) {
	var result Result

	if parsed == nil {
		return result, errors.New("nil ELF result")
	}

	if (parsed.Image == nil) == (parsed.Object == nil) {
		return result, errors.New(
			"ELF result must have exactly one image or object",
		)
	}

	spans, err := executableSpans(parsed)
	if err != nil {
		return result, err
	}

	for _, source := range spans {
		image := parsed.Image

		if parsed.Object != nil {
			image, err = sectionImage(parsed, source)
			if err != nil {
				return result, fmt.Errorf(
					"section %s: %w", source.name, err,
				)
			}
		}

		section := DecodedSection{
			Index: source.index,
			Name:  source.name,
		}

		for _, part := range armCodeSpans(parsed, source) {
			if part.data {
				result.SkippedDataBytes +=
					part.end - part.start
				continue
			}

			if err := decodeSpan(
				image,
				part,
				source.index,
				&section,
				&result,
			); err != nil {
				return result, fmt.Errorf(
					"decode %s at %#x: %w",
					source.name,
					part.start,
					err,
				)
			}
		}

		attachRelocations(
			&section,
			parsed,
			parsed.Object != nil,
		)

		result.Sections = append(result.Sections, section)
	}

	return result, nil
}

func (result *Result) diagnostic(
	section int,
	address, size uint64,
	reason error,
) {
	result.SkippedBytes += size

	if len(result.Diagnostics) == maxDiagnostics {
		result.SuppressedDiagnostics++
		return
	}

	result.Diagnostics = append(
		result.Diagnostics,
		Diagnostic{
			Section: section,
			Address: address,
			Size:    size,
			Reason:  reason.Error(),
		},
	)
}

func decodeSpan(
	image *binary.Image,
	part codeSpan,
	sectionIndex int,
	section *DecodedSection,
	result *Result,
) error {
	if part.mode == ModeThumb {
		return decodeThumbSpan(
			image, part, sectionIndex, section, result,
		)
	}

	step := uint64(1)

	switch image.Info.Architecture {
	case binary.ArchARM, binary.ArchARM64:
		step = 4

	case binary.ArchRISCV64:
		step = 2
	}

	for address := part.start; address < part.end; {
		inst, err := DecodeAtMode(
			image, address, part.mode,
		)

		if err == nil &&
			uint64(inst.Size) > part.end-address {
			err = ErrTruncatedInstruction
		}

		if err != nil {
			if !errors.Is(err, ErrInvalidInstruction) &&
				!errors.Is(err, ErrTruncatedInstruction) {
				return err
			}

			skipped := min(step, part.end-address)

			result.diagnostic(
				sectionIndex,
				address,
				skipped,
				err,
			)

			address += skipped
			continue
		}

		section.Instructions = append(
			section.Instructions, inst,
		)
		address += uint64(inst.Size)
	}

	return nil
}

// Thumb IT blocks require stateful range decoding.
func decodeThumbSpan(
	image *binary.Image,
	part codeSpan,
	sectionIndex int,
	section *DecodedSection,
	result *Result,
) error {
	if image.Info.Endianness != binary.LittleEndian {
		return ErrUnsupportedArchitecture
	}

	if part.start%2 != 0 {
		return fmt.Errorf(
			"%w: unaligned Thumb start",
			ErrInvalidRange,
		)
	}

	// A trailing byte cannot form a Thumb halfword.
	if part.end%2 != 0 {
		result.diagnostic(
			sectionIndex,
			part.end-1,
			1,
			ErrTruncatedInstruction,
		)
		part.end--
	}

	for address := part.start; address < part.end; {
		size := min(
			part.end-address,
			uint64(binary.MaxReadSize),
		)

		instructions, err := DecodeRangeMode(
			image, address, size, ModeThumb,
		)

		var consumed uint64

		for _, inst := range instructions {
			consumed += uint64(inst.Size)
		}

		section.Instructions = append(
			section.Instructions,
			instructions...,
		)

		address += consumed

		if err == nil {
			continue
		}

		if !errors.Is(err, ErrInvalidInstruction) &&
			!errors.Is(err, ErrTruncatedInstruction) {
			return err
		}

		// Retry a potentially incomplete Thumb-2 instruction
		// when the chunk boundary interrupts its bytes.
		if part.end-address > size-consumed &&
			size-consumed < 4 {
			continue
		}

		skipped := min(
			uint64(2),
			part.end-address,
		)

		if skipped == 0 {
			return fmt.Errorf(
				"%w: decoder made no progress",
				ErrInvalidInstruction,
			)
		}

		result.diagnostic(
			sectionIndex,
			address,
			skipped,
			err,
		)

		address += skipped
	}

	return nil
}
