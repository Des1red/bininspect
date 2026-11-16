package functions

import (
	"bytes"
	"debug/elf"
	stdbin "encoding/binary"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func makeEHFrame(
	sectionAddr, start uint64,
	length uint32,
) []byte {
	cieBody := []byte{
		0, 0, 0, 0,
		1, 'z', 'R', 0,
		1, 0x78, 16,
		1, 0x1b,
	}

	data := make([]byte, 4+len(cieBody))
	stdbin.LittleEndian.PutUint32(
		data[:4],
		uint32(len(cieBody)),
	)
	copy(data[4:], cieBody)

	idPosition := len(data) + 4
	pointerPosition := idPosition + 4

	payload := make([]byte, 13)

	stdbin.LittleEndian.PutUint32(
		payload[:4],
		uint32(idPosition),
	)

	delta := int64(start) -
		int64(sectionAddr+uint64(pointerPosition))

	stdbin.LittleEndian.PutUint32(
		payload[4:8],
		uint32(int32(delta)),
	)
	stdbin.LittleEndian.PutUint32(
		payload[8:12],
		length,
	)

	record := make([]byte, 4+len(payload))
	stdbin.LittleEndian.PutUint32(
		record[:4],
		uint32(len(payload)),
	)
	copy(record[4:], payload)

	return append(data, record...)
}

func TestEHFrameRecovery(t *testing.T) {
	const sectionAddr = 0x4000

	data := makeEHFrame(sectionAddr, 0x1000, 8)

	info := binary.Info{
		Format:       binary.FormatELF,
		Architecture: binary.ArchX8664,
		Bits:         64,
		Endianness:   binary.LittleEndian,
	}

	image, err := binary.NewImage(
		bytes.NewReader(data),
		uint64(len(data)),
		info,
		[]binary.Region{{
			Name:        ".eh_frame",
			Address:     sectionAddr,
			MemorySize:  uint64(len(data)),
			FileSize:    uint64(len(data)),
			Permissions: binary.PermRead,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	parsed := &binary.ELFResult{
		Info:   info,
		Header: elf.FileHeader{Type: elf.ET_DYN},
		Sections: []elf.SectionHeader{{
			Name: ".eh_frame",
			Addr: sectionAddr,
			Size: uint64(len(data)),
		}},
		Image: image,
	}

	ranges := UnwindRanges(parsed)

	if len(ranges) != 1 ||
		ranges[0].Start != 0x1000 ||
		ranges[0].End != 0x1008 {
		t.Fatalf("incorrect unwind range: %+v", ranges)
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 5,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{Address: 0x1000, Size: 4},
				{Address: 0x1004, Size: 4},
				{Address: 0x1008, Size: 4},
			},
		}},
	}

	leaders := Leaders(parsed, decoded)

	if !leaders[0][0x1000] ||
		!leaders[0][0x1008] {
		t.Fatalf("missing unwind boundaries: %+v", leaders)
	}

	graph := cfg.Graph{
		Section: 5,
		Name:    ".text",
		Blocks: []cfg.Block{
			{
				Start: 0x1000,
				End:   0x1004,
				Instructions: []decoder.Instruction{
					{Address: 0x1000, Size: 4},
				},
			},
			{
				Start: 0x1004,
				End:   0x1008,
				Instructions: []decoder.Instruction{
					{Address: 0x1004, Size: 4},
				},
			},
			{
				Start: 0x1008,
				End:   0x100c,
				Instructions: []decoder.Instruction{
					{Address: 0x1008, Size: 4},
				},
			},
		},
		Edges: []cfg.Edge{
			{From: 0, To: 1},
			{From: 1, To: 2},
		},
	}

	funcs := Recover(parsed, []cfg.Graph{graph})

	if len(funcs) != 1 {
		t.Fatalf("expected one function: %+v", funcs)
	}

	fn := funcs[0]

	if fn.Entry != 0x1000 ||
		fn.Source != "eh-frame" ||
		len(fn.Blocks) != 2 {
		t.Fatalf("incorrect function boundaries: %+v", fn)
	}
}

func TestMalformedEHFrame(t *testing.T) {
	for _, input := range [][]byte{
		{1, 2, 3},
		{0xff, 0xff, 0xff, 0xff},
		{9, 0, 0, 0, 0},
	} {
		_ = parseEHFrame(input, 0x4000, 8)
	}
}

func TestOverlappingFrameBounds(t *testing.T) {
	graph := cfg.Graph{
		Blocks: []cfg.Block{
			{Start: 0x1000, End: 0x1004},
			{Start: 0x1004, End: 0x1008},
			{Start: 0x1008, End: 0x100c},
		},
	}

	got := frameBounds(graph, []UnwindRange{
		{Start: 0x1000, End: 0x1008},
		{Start: 0x1004, End: 0x100c},
	})

	if len(got) != 0 {
		t.Fatalf("overlapping FDEs accepted: %+v", got)
	}
}
