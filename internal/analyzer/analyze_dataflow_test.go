package analyzer

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestAnalyzeELFDataflowIntegration(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format:       binary.FormatELF,
			Architecture: binary.ArchX8664,
			Bits:         64,
			Entry:        0x1000,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{
					Address:  0x1000,
					Size:     5,
					Mnemonic: "MOV",
					Operands: []decoder.Operand{
						{
							Kind:     decoder.OperandRegister,
							Register: "EDI",
						},
						{
							Kind:      decoder.OperandImmediate,
							Immediate: 42,
						},
					},
				},
				{
					Address:  0x1005,
					Size:     5,
					Mnemonic: "CALL",
					Flow:     decoder.FlowCall,
					Relocations: []decoder.RelocationReference{{
						SymbolName: "print_value",
					}},
				},
				{
					Address:  0x100a,
					Size:     1,
					Mnemonic: "RET",
					Flow:     decoder.FlowReturn,
				},
			},
		}},
	}

	got, err := AnalyzeELF(parsed, decoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Functions) != 1 ||
		!got.DataFlow.Supported ||
		len(got.DataFlow.Calls) != 1 {
		t.Fatalf("pipeline: %+v", got)
	}

	call := got.DataFlow.Calls[0]

	if call.Target != "print_value" ||
		call.Arguments[0].Value.Kind != "constant" ||
		call.Arguments[0].Value.Number != 42 {
		t.Fatalf("call evidence: %+v", call)
	}
}
