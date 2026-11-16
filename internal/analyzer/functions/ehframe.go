package functions

import (
	stdbin "encoding/binary"
	"math"
	"sort"

	"bininspect/internal/binary"
)

type UnwindRange struct {
	Start uint64
	End   uint64
}

// UnwindRanges reads supported .eh_frame FDEs from
// linked x86/x86-64 ELF images.
//
// Unknown encodings and malformed records are skipped.
// ET_REL and unsupported architectures retain the existing
// function-recovery behavior.
func UnwindRanges(parsed *binary.ELFResult) []UnwindRange {
	if parsed == nil || parsed.Image == nil ||
		(parsed.Info.Architecture != binary.ArchX86 &&
			parsed.Info.Architecture != binary.ArchX8664) {
		return nil
	}

	pointerSize := 4
	if parsed.Info.Architecture == binary.ArchX8664 {
		pointerSize = 8
	}

	var ranges []UnwindRange

	for _, section := range parsed.Sections {
		if section.Name != ".eh_frame" ||
			section.Size == 0 ||
			section.Size > binary.MaxReadSize {
			continue
		}

		data, err := parsed.Image.ReadVirtual(
			section.Addr,
			section.Size,
		)
		if err != nil {
			continue
		}

		ranges = append(
			ranges,
			parseEHFrame(data, section.Addr, pointerSize)...,
		)
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start != ranges[j].Start {
			return ranges[i].Start < ranges[j].Start
		}
		return ranges[i].End < ranges[j].End
	})

	unique := ranges[:0]

	for _, r := range ranges {
		if len(unique) == 0 ||
			unique[len(unique)-1] != r {
			unique = append(unique, r)
		}
	}

	return unique
}

type cieInfo struct {
	encoding byte
	aug      bool
}

func parseEHFrame(
	data []byte,
	sectionAddr uint64,
	pointerSize int,
) []UnwindRange {
	cies := make(map[int]cieInfo)
	var ranges []UnwindRange

	for pos := 0; pos+4 <= len(data); {
		size := stdbin.LittleEndian.Uint32(data[pos:])

		if size == 0 {
			break
		}

		// Extended DWARF64 record lengths are not
		// implemented in this initial reader.
		if size == math.MaxUint32 ||
			size < 4 ||
			uint64(size) > uint64(len(data)-pos-4) {
			break
		}

		end := pos + 4 + int(size)
		idPos := pos + 4
		id := stdbin.LittleEndian.Uint32(data[idPos:])
		payload := idPos + 4

		if id == 0 {
			if cie, ok := parseCIE(
				data[payload:end],
				pointerSize,
			); ok {
				cies[pos] = cie
			}
		} else if uint64(id) <= uint64(idPos) {
			if cie, ok := cies[idPos-int(id)]; ok {
				if r, ok := parseFDE(
					data,
					payload,
					end,
					sectionAddr,
					pointerSize,
					cie,
				); ok {
					ranges = append(ranges, r)
				}
			}
		}

		pos = end
	}

	return ranges
}

func readULEB(
	data []byte,
	at *int,
) (uint64, bool) {
	var value uint64

	for shift := uint(0); shift < 70; shift += 7 {
		if *at >= len(data) {
			return 0, false
		}

		b := data[*at]
		*at++

		payload := uint64(b & 0x7f)

		if shift == 63 && payload > 1 {
			return 0, false
		}
		if shift > 63 && payload != 0 {
			return 0, false
		}

		value |= payload << shift

		if b < 0x80 {
			return value, true
		}
	}

	return 0, false
}

func skipSLEB(data []byte, at *int) bool {
	for i := 0; i < 10; i++ {
		if *at >= len(data) {
			return false
		}

		b := data[*at]
		*at++

		if b < 0x80 {
			return true
		}
	}

	return false
}

func skipEncodedPointer(
	data []byte,
	at *int,
	encoding byte,
	pointerSize int,
) bool {
	// Aligned pointers require additional layout handling.
	if encoding&0x70 == 0x50 {
		return false
	}

	var size int

	switch encoding & 0x0f {
	case 0:
		size = pointerSize
	case 2, 10:
		size = 2
	case 3, 11:
		size = 4
	case 4, 12:
		size = 8
	case 1:
		_, ok := readULEB(data, at)
		return ok
	case 9:
		return skipSLEB(data, at)
	default:
		return false
	}

	if size > len(data)-*at {
		return false
	}

	*at += size
	return true
}

func parseCIE(
	data []byte,
	pointerSize int,
) (cieInfo, bool) {
	var cie cieInfo

	if len(data) < 2 ||
		(data[0] != 1 && data[0] != 3) {
		return cie, false
	}

	at := 1
	augEnd := at

	for augEnd < len(data) && data[augEnd] != 0 {
		augEnd++
	}

	if augEnd == len(data) {
		return cie, false
	}

	augmentation := string(data[at:augEnd])
	at = augEnd + 1

	if _, ok := readULEB(data, &at); !ok ||
		!skipSLEB(data, &at) {
		return cie, false
	}

	if data[0] == 1 {
		if at == len(data) {
			return cie, false
		}
		at++
	} else {
		if _, ok := readULEB(data, &at); !ok {
			return cie, false
		}
	}

	if augmentation == "" {
		return cie, true
	}

	if augmentation[0] != 'z' {
		return cie, false
	}

	cie.aug = true

	size, ok := readULEB(data, &at)
	if !ok || size > uint64(len(data)-at) {
		return cie, false
	}

	extra := data[at : at+int(size)]
	extraAt := 0

	for i := 1; i < len(augmentation); i++ {
		switch augmentation[i] {
		case 'R':
			if extraAt >= len(extra) {
				return cie, false
			}

			cie.encoding = extra[extraAt]
			extraAt++

		case 'L':
			if extraAt >= len(extra) {
				return cie, false
			}
			extraAt++

		case 'P':
			if extraAt >= len(extra) {
				return cie, false
			}

			encoding := extra[extraAt]
			extraAt++

			if !skipEncodedPointer(
				extra,
				&extraAt,
				encoding,
				pointerSize,
			) {
				return cie, false
			}

		case 'S':
			// Signal-frame marker; no augmentation data.

		default:
			return cie, false
		}
	}

	return cie, true
}

func readPointer(
	data []byte,
	at *int,
	encoding byte,
	pointerSize int,
) (uint64, bool) {
	switch encoding & 0x0f {
	case 0:
		if pointerSize == 8 && *at <= len(data)-8 {
			n := stdbin.LittleEndian.Uint64(data[*at:])
			*at += 8
			return n, true
		}

		if pointerSize == 4 && *at <= len(data)-4 {
			n := uint64(stdbin.LittleEndian.Uint32(data[*at:]))
			*at += 4
			return n, true
		}

	case 3:
		if *at <= len(data)-4 {
			n := uint64(stdbin.LittleEndian.Uint32(data[*at:]))
			*at += 4
			return n, true
		}

	case 11:
		if *at <= len(data)-4 {
			n := uint64(int64(int32(
				stdbin.LittleEndian.Uint32(data[*at:]),
			)))
			*at += 4
			return n, true
		}
	}

	return 0, false
}

func parseFDE(
	data []byte,
	at, end int,
	sectionAddr uint64,
	pointerSize int,
	cie cieInfo,
) (UnwindRange, bool) {
	encoding := cie.encoding

	// Indirect pointers require dereferencing relocated data.
	if encoding&0x80 != 0 {
		return UnwindRange{}, false
	}

	pointerPosition := at

	value, ok := readPointer(
		data[:end], &at, encoding, pointerSize,
	)
	if !ok {
		return UnwindRange{}, false
	}

	start := value

	switch encoding & 0x70 {
	case 0:
		// Absolute pointer.

	case 0x10:
		// PC-relative to the encoded pointer's location.
		base := sectionAddr + uint64(pointerPosition)
		if base < sectionAddr {
			return UnwindRange{}, false
		}

		offset := int64(value)

		if offset < 0 {
			if offset == math.MinInt64 ||
				uint64(-offset) > base {
				return UnwindRange{}, false
			}

			start = base - uint64(-offset)
		} else {
			if uint64(offset) > math.MaxUint64-base {
				return UnwindRange{}, false
			}

			start = base + uint64(offset)
		}

	default:
		return UnwindRange{}, false
	}

	// The range uses the pointer's data format,
	// not its PC-relative application.
	span, ok := readPointer(
		data[:end],
		&at,
		encoding&0x0f,
		pointerSize,
	)

	if !ok || span == 0 ||
		start > math.MaxUint64-span {
		return UnwindRange{}, false
	}

	if cie.aug {
		size, ok := readULEB(data[:end], &at)

		if !ok || size > uint64(end-at) {
			return UnwindRange{}, false
		}
	}

	return UnwindRange{
		Start: start,
		End:   start + span,
	}, true
}
