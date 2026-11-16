package resolve

import (
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/decoder"
)

func TestSignedRelativeTableTargets(t *testing.T) {
	// Actual first three entries observed in /bin/ls.
	raw := []byte{
		0xbc, 0x6b, 0xfe, 0xff,
		0x4d, 0x82, 0xfe, 0xff,
		0x30, 0x82, 0xfe, 0xff,
	}

	starts := map[uint64]bool{
		0x1dd0: true,
		0x3461: true,
		0x3444: true,
	}

	targets, ok := relativeTableTargets(
		raw,
		0x1b214,
		0x1540,
		0x3903,
		starts,
	)

	if !ok {
		t.Fatal("valid signed table was rejected")
	}

	want := []uint64{0x1dd0, 0x3444, 0x3461}

	if len(targets) != len(want) {
		t.Fatalf("targets=%#v, want=%#v", targets, want)
	}

	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf(
				"target[%d]=%#x, want %#x",
				i, targets[i], want[i],
			)
		}
	}
}

func TestRejectInvalidJumpTableTarget(t *testing.T) {
	raw := []byte{
		0xbc, 0x6b, 0xfe, 0xff,
	}

	targets, ok := relativeTableTargets(
		raw,
		0x1b214,
		0x1540,
		0x3903,
		map[uint64]bool{},
	)

	if ok || len(targets) != 0 {
		t.Fatalf("invalid target accepted: %#v", targets)
	}
}

func TestAddJumpTableEdges(t *testing.T) {
	graphs := []cfg.Graph{{
		Section: 5,
		Blocks: []cfg.Block{
			{
				Start: 0x16d3,
				End:   0x16dd,
				Instructions: []decoder.Instruction{
					{
						Address:  0x16da,
						Mnemonic: "JMP",
						Flow:     decoder.FlowJump,
						Indirect: true,
					},
				},
			},
			{Start: 0x1dd0, End: 0x1dd4},
			{Start: 0x3444, End: 0x3448},
		},
		Edges: []cfg.Edge{
			{
				From: 0,
				To:   -1,
				Kind: cfg.EdgeIndirect,
			},
		},
	}}

	AddJumpTableEdges(
		graphs,
		[]JumpTable{{
			Section:  5,
			Dispatch: 0x16da,
			Targets:  []uint64{0x1dd0, 0x3444},
		}},
	)

	found := make(map[int]bool)

	for _, edge := range graphs[0].Edges {
		if edge.From == 0 {
			found[edge.To] = true
		}
	}

	if !found[1] || !found[2] || found[-1] {
		t.Fatalf(
			"incorrect resolved edges: %+v",
			graphs[0].Edges,
		)
	}
}
