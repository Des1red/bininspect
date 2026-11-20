package findings

import (
	"strings"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/decoder"
)

func TestManualGuidanceI386Gets(t *testing.T) {
	reg := func(name string) decoder.Operand {
		return decoder.Operand{
			Kind:     decoder.OperandRegister,
			Register: name,
		}
	}

	mem := func(offset int64) decoder.Operand {
		return decoder.Operand{
			Kind: decoder.OperandMemory,
			Memory: decoder.Memory{
				Base:         "ESP",
				Displacement: offset,
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

	graph := cfg.Graph{
		Section: 14,
		Name:    ".text",

		Blocks: []cfg.Block{
			{
				Start: 0x80483f4,
				End:   0x8048411,

				Instructions: []decoder.Instruction{
					{
						Address:  0x80483fd,
						Mnemonic: "MOV",
						Operands: []decoder.Operand{
							mem(0x5c),
							imm(0),
						},
					},
					{
						Address:  0x8048405,
						Mnemonic: "LEA",
						Operands: []decoder.Operand{
							reg("EAX"),
							mem(0x1c),
						},
					},
					{
						Address:  0x8048409,
						Mnemonic: "MOV",
						Operands: []decoder.Operand{
							mem(0),
							reg("EAX"),
						},
					},
					{
						Address:  0x804840c,
						Mnemonic: "CALL",
						Operands: []decoder.Operand{
							imm(0x804830c),
						},
					},
				},
			},
			{
				Start: 0x8048411,
				End:   0x8048419,

				Instructions: []decoder.Instruction{
					{
						Address:  0x8048411,
						Mnemonic: "MOV",
						Operands: []decoder.Operand{
							reg("EAX"),
							mem(0x5c),
						},
					},
					{
						Address:  0x8048415,
						Mnemonic: "TEST",
						Operands: []decoder.Operand{
							reg("EAX"),
							reg("EAX"),
						},
					},
					{
						Address:  0x8048417,
						Mnemonic: "JE",
						Operands: []decoder.Operand{
							imm(0x8048427),
						},
					},
				},
			},
		},

		Edges: []cfg.Edge{
			{
				From: 0,
				To:   1,
				Kind: cfg.EdgeFallthrough,
			},
		},
	}

	flow := dataflow.Result{
		Calls: []dataflow.CallTrace{
			{
				Function: "main",
				Section:  14,
				Address:  0x804840c,
				Target:   "gets",

				Arguments: []dataflow.Argument{
					{
						Position: 1,
						Location: "[esp+0]",

						Value: dataflow.Value{
							Kind:        "stack-address",
							Origin:      "aligned-SP",
							StackOffset: -68,
						},
					},
				},
			},
		},
	}

	items := []Finding{
		{ID: "API-gets-14-804840c"},
		{ID: "SEC-NONPIE"},
		{ID: "IMPORT-gets"},
	}

	got := AddManualGuidance(
		items,
		flow,
		[]cfg.Graph{graph},
	)

	if got[0].ManualGuidance == nil {
		t.Fatal("missing gets manual guidance")
	}

	guide := got[0].ManualGuidance

	if !guide.HasCandidateDistance {
		t.Fatal("expected a candidate offset")
	}

	if guide.CandidateDistance != 64 {
		t.Fatalf(
			"candidate distance=%d, want 64",
			guide.CandidateDistance,
		)
	}

	if !strings.Contains(
		strings.Join(guide.Steps, "\n"),
		"aligned-SP-4",
	) {
		t.Fatalf(
			"missing checked stack location: %+v",
			guide.Steps,
		)
	}

	if got[1].ManualGuidance != nil {
		t.Fatal("hardening finding gained API guidance")
	}

	if got[2].ManualGuidance != nil {
		t.Fatal("import-only finding gained call guidance")
	}

	// Remove the conditional branch evidence.
	// The analyzer must not infer a numeric offset.
	graph.Blocks[1].Instructions[2].Mnemonic = "NOP"

	got = AddManualGuidance(
		items,
		flow,
		[]cfg.Graph{graph},
	)

	if got[0].ManualGuidance == nil {
		t.Fatal("general guidance should remain available")
	}

	if got[0].ManualGuidance.HasCandidateDistance {
		t.Fatal("invented offset without a checked branch")
	}

	// Remove the modeled argument evidence too.
	flow.Calls[0].Arguments = nil

	got = AddManualGuidance(
		items,
		flow,
		[]cfg.Graph{graph},
	)

	if got[0].ManualGuidance == nil {
		t.Fatal("expected general manual guidance")
	}

	if got[0].ManualGuidance.HasCandidateDistance {
		t.Fatal("invented offset without argument evidence")
	}
}
