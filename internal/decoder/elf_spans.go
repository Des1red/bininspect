package decoder

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"bininspect/internal/binary"
)

type codeSpan struct {
	index      int
	name       string
	start, end uint64
	mode       DecodeMode
	data       bool
}

func executableSpans(
	parsed *binary.ELFResult,
) ([]codeSpan, error) {
	var result []codeSpan

	if parsed.Object != nil {
		for _, sec := range parsed.Object.Sections() {
			if sec.Size == 0 ||
				sec.Type == elf.SHT_NOBITS ||
				sec.Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}

			result = append(result, codeSpan{
				index: sec.Index,
				name:  sec.Name,
				start: 0,
				end:   sec.Size,
			})
		}

		return result, nil
	}

	regions := parsed.Image.Regions()
	hasExecutableSections := false

	for index, sec := range parsed.Sections {
		if sec.Size == 0 ||
			sec.Type == elf.SHT_NOBITS ||
			sec.Flags&elf.SHF_EXECINSTR == 0 ||
			sec.Flags&elf.SHF_ALLOC == 0 {
			continue
		}

		hasExecutableSections = true

		if sec.Addr > math.MaxUint64-sec.Size {
			return nil, fmt.Errorf(
				"executable section %d address overflow",
				index,
			)
		}

		end := sec.Addr + sec.Size

		for _, region := range regions {
			if region.Permissions&binary.PermExecute == 0 ||
				region.FileSize == 0 {
				continue
			}

			start := max(sec.Addr, region.Address)
			stop := min(
				end,
				region.Address+region.FileSize,
			)

			if start < stop {
				result = append(result, codeSpan{
					index: index,
					name:  sec.Name,
					start: start,
					end:   stop,
				})
			}
		}
	}

	if hasExecutableSections {
		if len(result) == 0 {
			return nil, fmt.Errorf(
				"ELF executable sections have no file-backed executable mapping",
			)
		}

		return result, nil
	}

	// Sectionless ELF: use executable PT_LOAD regions.
	for _, region := range regions {
		if region.Permissions&binary.PermExecute == 0 ||
			region.FileSize == 0 {
			continue
		}

		result = append(result, codeSpan{
			index: -1,
			name:  region.Name,
			start: region.Address,
			end:   region.Address + region.FileSize,
		})
	}

	return result, nil
}

// ARM mapping symbols identify ARM code, Thumb code,
// and data embedded in executable sections.
func armCodeSpans(
	parsed *binary.ELFResult,
	source codeSpan,
) []codeSpan {
	if parsed.Info.Architecture != binary.ArchARM {
		return []codeSpan{source}
	}

	mode := ModeARM

	if parsed.Object == nil &&
		parsed.Info.Entry&1 != 0 {
		mode = ModeThumb
	}

	type marker struct {
		at   uint64
		mode DecodeMode
		data bool
	}

	var markers []marker

	for _, sym := range parsed.Metadata.Symbols {
		if source.index >= 0 &&
			sym.SectionIndex != uint32(source.index) {
			continue
		}

		name := sym.Name

		if len(name) > 2 && name[2] != '.' {
			continue
		}

		var m marker

		switch {
		case name == "$a" ||
			strings.HasPrefix(name, "$a."):
			m.mode = ModeARM

		case name == "$t" ||
			strings.HasPrefix(name, "$t."):
			m.mode = ModeThumb

		case name == "$d" ||
			strings.HasPrefix(name, "$d."):
			m.data = true

		default:
			continue
		}

		m.at = sym.Value

		if m.at <= source.end {
			markers = append(markers, m)
		}
	}

	sort.SliceStable(markers, func(i, j int) bool {
		return markers[i].at < markers[j].at
	})

	cursor := source.start
	data := false

	var spans []codeSpan

	for _, m := range markers {
		if m.at <= cursor {
			mode, data = m.mode, m.data
			continue
		}

		if m.at >= source.end {
			break
		}

		part := source
		part.start = cursor
		part.end = m.at
		part.mode = mode
		part.data = data

		spans = append(spans, part)

		cursor = m.at
		mode = m.mode
		data = m.data
	}

	if cursor < source.end {
		part := source
		part.start = cursor
		part.mode = mode
		part.data = data

		spans = append(spans, part)
	}

	return spans
}

// ET_REL uses section-relative addresses.
//
// Create a temporary Image to reuse the existing
// architecture decoders without modifying their APIs.
func sectionImage(
	parsed *binary.ELFResult,
	source codeSpan,
) (*binary.Image, error) {
	var reader io.ReaderAt = sectionReader{
		object: parsed.Object,
		index:  source.index,
	}

	if source.end <= binary.MaxReadSize {
		data, err := parsed.Object.ReadSection(
			source.index, 0, source.end,
		)
		if err != nil {
			return nil, err
		}

		reader = bytes.NewReader(data)
	}

	return binary.NewImage(
		reader,
		source.end,
		parsed.Info,
		[]binary.Region{{
			Name:       source.name,
			Address:    0,
			MemorySize: source.end,
			FileSize:   source.end,
			Permissions: binary.PermRead |
				binary.PermExecute,
		}},
	)
}

type sectionReader struct {
	object *binary.ELFObject
	index  int
}

func (reader sectionReader) ReadAt(
	dst []byte,
	offset int64,
) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf(
			"negative section offset",
		)
	}

	data, err := reader.object.ReadSection(
		reader.index,
		uint64(offset),
		uint64(len(dst)),
	)
	if err != nil {
		return 0, err
	}

	return copy(dst, data), nil
}
