package cfg

import (
	"testing"

	"bininspect/internal/decoder"
)

func instr(
	address uint64,
	size uint8,
	flow decoder.FlowKind,
	target uint64,
) decoder.Instruction {
	return decoder.Instruction{
		Address:   address,
		Size:      size,
		Flow:      flow,
		Target:    target,
		HasTarget: target != 0,
	}
}

func TestConditionalAndCall(t *testing.T) {
	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				instr(0x1000, 1, decoder.FlowNone, 0),
				instr(0x1001, 2, decoder.FlowConditional, 0x1005),
				instr(0x1003, 2, decoder.FlowCall, 0x9000),
				instr(0x1005, 1, decoder.FlowReturn, 0),
				instr(0x1006, 1, decoder.FlowNone, 0),
			},
		}},
	}

	got, err := Build(decoded)
	if err != nil {
		t.Fatal(err)
	}

	g := got[0]

	if len(g.Blocks) != 4 ||
		len(g.Edges) != 3 ||
		len(g.Calls) != 1 {
		t.Fatalf("unexpected graph: %+v", g)
	}

	if g.Edges[0].Kind != EdgeConditional ||
		g.Edges[0].To != 2 ||
		g.Edges[1].Kind != EdgeConditionalFalse ||
		g.Edges[1].To != 1 {
		t.Fatalf("incorrect branch edges: %+v", g.Edges)
	}

	if g.Edges[2].Kind != EdgeFallthrough ||
		g.Edges[2].To != 2 ||
		!g.Calls[0].HasTarget {
		t.Fatalf("incorrect call: %+v", g)
	}
}

func TestGapNoImplicitEdge(t *testing.T) {
	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Instructions: []decoder.Instruction{
				instr(0x1000, 1, decoder.FlowNone, 0),
				instr(0x1004, 1, decoder.FlowReturn, 0),
			},
		}},
	}

	got, err := Build(decoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(got[0].Blocks) != 2 ||
		len(got[0].Edges) != 0 {
		t.Fatalf("CFG crossed undecoded bytes: %+v", got[0])
	}
}

func TestRelocationIsUnresolved(t *testing.T) {
	branch := instr(
		0x1000, 2, decoder.FlowJump, 0x1002,
	)
	branch.Relocations = []decoder.RelocationReference{{
		SymbolName: "external",
	}}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Instructions: []decoder.Instruction{
				branch,
				instr(0x1002, 1, decoder.FlowReturn, 0),
			},
		}},
	}

	got, err := Build(decoded)
	if err != nil {
		t.Fatal(err)
	}

	edge := got[0].Edges[0]

	if edge.To != -1 || edge.Symbol != "external" {
		t.Fatalf("relocation incorrectly resolved: %+v", edge)
	}
}

func TestSeparateObjectSections(t *testing.T) {
	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{
			{
				Index: 1,
				Instructions: []decoder.Instruction{
					instr(0, 1, decoder.FlowReturn, 0),
				},
			},
			{
				Index: 2,
				Instructions: []decoder.Instruction{
					instr(0, 1, decoder.FlowReturn, 0),
				},
			},
		},
	}

	got, err := Build(decoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 ||
		got[0].Section != 1 ||
		got[1].Section != 2 {
		t.Fatalf("ELF object sections were merged: %+v", got)
	}
}

func TestOverlappingInstructions(t *testing.T) {
	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Instructions: []decoder.Instruction{
				instr(0, 3, decoder.FlowNone, 0),
				instr(2, 1, decoder.FlowReturn, 0),
			},
		}},
	}

	if _, err := Build(decoded); err == nil {
		t.Fatal("accepted overlapping instructions")
	}
}
