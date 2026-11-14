package findings

import (
	"debug/elf"
	"strings"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/analyzer/security"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func parsedExecutable() *binary.ELFResult {
	return &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_EXEC},
	}
}

func byID(found []Finding, id string) (Finding, bool) {
	for _, f := range found {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func TestNamedCallAndTypedArgument(t *testing.T) {
	parsed := parsedExecutable()

	graphs := []cfg.Graph{{
		Section: 3,
		Calls: []cfg.CallSite{{
			Address: 0x1000,
			Symbol:  "gets@GLIBC_2.0",
		}},
	}}

	flow := dataflow.Result{
		Supported: true,
		Calls: []dataflow.CallTrace{{
			Section:  3,
			Address:  0x1000,
			Function: "main",
			Target:   "gets@GLIBC_2.0",
			Arguments: []dataflow.Argument{{
				Position: 1,
				Location: "rdi",
				Value: dataflow.Value{
					Kind:        "stack-address",
					StackOffset: -48,
				},
			}},
		}},
	}

	got := Evaluate(
		parsed, graphs, flow, security.Result{},
	)

	f, ok := byID(got, "API-gets-3-1000")

	if !ok ||
		f.Severity != "high" ||
		!f.HasAddress ||
		len(f.Evidence) != 3 ||
		!strings.Contains(f.Evidence[2], "entry-SP-48") {
		t.Fatalf("missing call evidence: %+v", got)
	}
}

func TestImportOnlyLowConfidence(t *testing.T) {
	parsed := parsedExecutable()

	parsed.Metadata.Symbols = []binary.ELFSymbol{
		{
			Name:         "strcpy",
			Type:         elf.STT_FUNC,
			SectionIndex: 0,
		},
		{
			Name:         "__strcpy_chk",
			Type:         elf.STT_FUNC,
			SectionIndex: 0,
		},
	}

	got := Evaluate(
		parsed,
		nil,
		dataflow.Result{},
		security.Result{},
	)

	f, ok := byID(got, "IMPORT-strcpy")

	if !ok ||
		f.Severity != "info" ||
		f.Confidence != "low" ||
		len(got) != 1 {
		t.Fatalf("import misclassified: %+v", got)
	}
}

func TestRelocationSuppressesImportOnly(t *testing.T) {
	parsed := parsedExecutable()

	parsed.Metadata.Symbols = []binary.ELFSymbol{{
		Name:         "strcpy",
		Type:         elf.STT_FUNC,
		SectionIndex: 0,
	}}

	graphs := []cfg.Graph{{
		Section: 1,
		Calls: []cfg.CallSite{{
			Address: 0x1500,
			Symbol:  "strcpy",
		}},
	}}

	got := Evaluate(
		parsed,
		graphs,
		dataflow.Result{},
		security.Result{},
	)

	if len(got) != 1 ||
		got[0].ID != "API-strcpy-1-1500" {
		t.Fatalf("double counted: %+v", got)
	}
}

func TestHardeningFindingsOnlyWhenObserved(t *testing.T) {
	parsed := parsedExecutable()

	hardening := security.Result{
		NX: security.Check{
			Status:   "disabled",
			Evidence: []string{"PT_GNU_STACK PF_X"},
		},
		RWX: security.Check{
			Status: "present",
		},
		PIE: security.Check{
			Status: "disabled",
		},
		RELRO: security.Check{
			Status: "partial",
		},
	}

	got := Evaluate(
		parsed,
		nil,
		dataflow.Result{},
		hardening,
	)

	if len(got) != 4 {
		t.Fatalf("findings: %+v", got)
	}

	if got[0].ID != "SEC-RWX" {
		t.Fatalf("severity ordering: %+v", got)
	}

	for _, id := range []string{
		"SEC-EXECSTACK",
		"SEC-NONPIE",
		"SEC-PARTIAL-RELRO",
	} {
		if _, ok := byID(got, id); !ok {
			t.Fatalf("missing %s", id)
		}
	}

	empty := Evaluate(
		parsed,
		nil,
		dataflow.Result{},
		security.Result{},
	)

	if len(empty) != 0 {
		t.Fatal("unknown classified as disabled")
	}
}

func TestRelocatableHardening(t *testing.T) {
	parsed := &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_REL},
	}

	got := Evaluate(
		parsed,
		nil,
		dataflow.Result{},
		security.Result{
			PIE: security.Check{Status: "disabled"},
			RWX: security.Check{Status: "present"},
		},
	)

	if len(got) != 0 {
		t.Fatalf("ET_REL hardening leak: %+v", got)
	}
}

func TestNilInput(t *testing.T) {
	if got := Evaluate(
		nil,
		nil,
		dataflow.Result{},
		security.Result{},
	); len(got) != 0 {
		t.Fatalf("nil input: %+v", got)
	}
}

func TestRiskyCallThroughPLT(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Architecture: binary.ArchX8664,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
	}

	parsed.DynamicMetadata.Relocations = []binary.ELFRelocation{
		{
			Offset:     0x5000,
			Type:       uint32(elf.R_X86_64_JMP_SLOT),
			SymbolName: "strcpy@GLIBC_2.2.5",
		},
	}

	graphs := []cfg.Graph{
		{
			Name:    ".plt.sec",
			Section: 4,
			Blocks: []cfg.Block{
				{
					Start: 0x1000,
					Instructions: []decoder.Instruction{
						{
							Address:  0x1004,
							Size:     6,
							Flow:     decoder.FlowJump,
							Indirect: true,
							Operands: []decoder.Operand{
								{
									Kind: decoder.OperandMemory,
									Memory: decoder.Memory{
										Base:         "RIP",
										Displacement: 0x5000 - 0x100a,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:    ".text",
			Section: 5,
			Calls: []cfg.CallSite{
				{
					Address:   0x2000,
					Target:    0x1000,
					HasTarget: true,
				},
			},
		},
	}

	got := Evaluate(
		parsed,
		graphs,
		dataflow.Result{},
		security.Result{},
	)

	finding, exists := byID(
		got,
		"API-strcpy-5-2000",
	)

	if !exists || finding.Severity != "medium" {
		t.Fatalf(
			"missing risky PLT call finding: %+v",
			got,
		)
	}
}
