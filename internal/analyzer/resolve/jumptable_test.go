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

func TestGeneralizedJumpTableIndexGuards(t *testing.T) {
	reg := func(name string) decoder.Operand {
		return decoder.Operand{
			Kind:     decoder.OperandRegister,
			Register: name,
		}
	}

	rip := func(disp int64) decoder.Operand {
		return decoder.Operand{
			Kind: decoder.OperandMemory,
			Memory: decoder.Memory{
				Base:         "RIP",
				Displacement: disp,
				SizeBytes:    4,
			},
		}
	}

	imm := func(value int64) decoder.Operand {
		return decoder.Operand{
			Kind:      decoder.OperandImmediate,
			Immediate: value,
		}
	}

	tests := []struct {
		name   string
		cmp    decoder.Instruction
		middle []decoder.Instruction
		index  string
		want   bool
	}{
		{
			name: "original EAX to RAX",
			cmp: decoder.Instruction{
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					reg("EAX"), imm(276),
				},
			},
			index: "RAX",
			want:  true,
		},
		{
			name: "RBX as index",
			cmp: decoder.Instruction{
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					reg("RBX"), imm(9),
				},
			},
			index: "RBX",
			want:  true,
		},
		{
			name: "CL zero extended to RDX",
			cmp: decoder.Instruction{
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					reg("CL"), imm(122),
				},
			},
			middle: []decoder.Instruction{
				{
					Mnemonic: "MOVZX",
					Operands: []decoder.Operand{
						reg("EDX"), reg("CL"),
					},
				},
			},
			index: "RDX",
			want:  true,
		},
		{
			name: "same RIP relative global",
			cmp: decoder.Instruction{
				Address:  0xb4f0,
				Size:     7,
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					rip(110389), imm(4),
				},
			},
			middle: []decoder.Instruction{
				{
					Address:  0xb50c,
					Size:     6,
					Mnemonic: "MOV",
					Operands: []decoder.Operand{
						reg("EAX"), rip(110362),
					},
				},
			},
			index: "RAX",
			want:  true,
		},
		{
			name: "different RIP relative global",
			cmp: decoder.Instruction{
				Address:  0xb4f0,
				Size:     7,
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					rip(110389), imm(4),
				},
			},
			middle: []decoder.Instruction{
				{
					Address:  0xb50c,
					Size:     6,
					Mnemonic: "MOV",
					Operands: []decoder.Operand{
						reg("EAX"), rip(110363),
					},
				},
			},
			index: "RAX",
			want:  false,
		},
		{
			name: "overwritten index",
			cmp: decoder.Instruction{
				Mnemonic: "CMP",
				Operands: []decoder.Operand{
					reg("EAX"), imm(10),
				},
			},
			middle: []decoder.Instruction{
				{
					Mnemonic: "MOV",
					Operands: []decoder.Operand{
						reg("EAX"), imm(99),
					},
				},
			},
			index: "RAX",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexMatchesGuard(
				tt.cmp,
				tt.middle,
				tt.index,
			)

			if got != tt.want {
				t.Fatalf(
					"indexMatchesGuard=%t, want %t",
					got,
					tt.want,
				)
			}
		})
	}
}
