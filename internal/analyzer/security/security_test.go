package security

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
)

func TestELFFullRELROAndPIE(t *testing.T) {
	parsed := &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_DYN},
		Programs: []elf.ProgHeader{
			{
				Type:  elf.PT_LOAD,
				Flags: elf.PF_R | elf.PF_X,
				Memsz: 0x1000,
			},
			{
				Type:  elf.PT_GNU_STACK,
				Flags: elf.PF_R | elf.PF_W,
			},
			{
				Type:  elf.PT_GNU_RELRO,
				Memsz: 0x300,
			},
			{Type: elf.PT_INTERP},
		},
		Dynamic: binary.ELFDynamicInfo{
			Present: true,
			Entries: []binary.ELFDynamicEntry{{
				Tag: elf.DT_FLAGS_1,
				Value: uint64(
					elf.DF_1_NOW | elf.DF_1_PIE,
				),
			}},
		},
		Metadata: binary.ELFMetadata{
			Symbols: []binary.ELFSymbol{{
				Name: "__stack_chk_fail@GLIBC_2.4",
			}},
		},
		DynamicMetadata: binary.ELFDynamicMetadata{
			ELFMetadata: binary.ELFMetadata{
				Symbols: []binary.ELFSymbol{{
					Name: "__memcpy_chk",
				}},
			},
		},
	}

	got := Analyze(parsed)

	if got.NX.Status != "enabled" ||
		got.PIE.Status != "enabled" ||
		got.RELRO.Status != "full" ||
		got.Canary.Status != "detected" ||
		got.Fortify.Status != "detected" ||
		got.ASLR.Status != "compatible" ||
		got.RWX.Status != "not-observed" {
		t.Fatalf("incorrect security flags: %+v", got)
	}
}

func TestELFExecutableStackAndRWX(t *testing.T) {
	parsed := &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_EXEC},
		Programs: []elf.ProgHeader{
			{
				Type:  elf.PT_LOAD,
				Flags: elf.PF_R | elf.PF_W | elf.PF_X,
				Memsz: 16,
			},
			{
				Type:  elf.PT_GNU_STACK,
				Flags: elf.PF_R | elf.PF_W | elf.PF_X,
			},
		},
	}

	got := Analyze(parsed)

	if got.NX.Status != "disabled" ||
		got.PIE.Status != "disabled" ||
		got.RELRO.Status != "disabled" ||
		got.RWX.Status != "present" ||
		got.ASLR.Status != "limited" {
		t.Fatalf("incorrect executable analysis: %+v", got)
	}

	if got.Canary.Status != "not-observed" ||
		got.Fortify.Status != "not-observed" {
		t.Fatalf("false protection claims: %+v", got)
	}
}

func TestELFPartialRELROAndLikelyPIE(t *testing.T) {
	parsed := &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_DYN},
		Programs: []elf.ProgHeader{
			{
				Type:  elf.PT_GNU_RELRO,
				Memsz: 0x40,
			},
			{Type: elf.PT_INTERP},
		},
		Dynamic: binary.ELFDynamicInfo{
			Present: true,
		},
	}

	got := Analyze(parsed)

	if got.PIE.Status != "likely" ||
		got.RELRO.Status != "partial" ||
		got.NX.Status != "unknown" ||
		got.RWX.Status != "unknown" {
		t.Fatalf("incorrect tentative status: %+v", got)
	}
}

func TestELFRelocatableObject(t *testing.T) {
	parsed := &binary.ELFResult{
		Header: elf.FileHeader{Type: elf.ET_REL},
		Metadata: binary.ELFMetadata{
			Symbols: []binary.ELFSymbol{{
				Name: "__stack_chk_fail_local",
			}},
		},
	}

	got := Analyze(parsed)

	if got.NX.Status != "not-applicable" ||
		got.PIE.Status != "not-applicable" ||
		got.RELRO.Status != "not-applicable" ||
		got.Canary.Status != "detected" {
		t.Fatalf("incorrect ET_REL handling: %+v", got)
	}
}

func TestELFBindNowVariants(t *testing.T) {
	tags := []binary.ELFDynamicEntry{
		{Tag: elf.DT_BIND_NOW},
		{
			Tag:   elf.DT_FLAGS,
			Value: uint64(elf.DF_BIND_NOW),
		},
		{
			Tag:   elf.DT_FLAGS_1,
			Value: uint64(elf.DF_1_NOW),
		},
	}

	for _, tag := range tags {
		parsed := &binary.ELFResult{
			Header: elf.FileHeader{
				Type: elf.ET_EXEC,
			},
			Programs: []elf.ProgHeader{{
				Type:  elf.PT_GNU_RELRO,
				Memsz: 0x100,
			}},
			Dynamic: binary.ELFDynamicInfo{
				Present: true,
				Entries: []binary.ELFDynamicEntry{tag},
			},
		}

		got := Analyze(parsed)

		if got.RELRO.Status != "full" {
			t.Errorf(
				"tag %v: got %q",
				tag.Tag,
				got.RELRO.Status,
			)
		}
	}
}

func TestELFNilAndSharedObject(t *testing.T) {
	if got := Analyze(nil); got.NX.Status != "unknown" {
		t.Fatalf("nil result: %+v", got)
	}

	shared := &binary.ELFResult{
		Header: elf.FileHeader{
			Type: elf.ET_DYN,
		},
	}

	got := Analyze(shared)

	if got.PIE.Status != "not-applicable" ||
		got.ASLR.Status != "compatible" ||
		got.RELRO.Status != "unknown" {
		t.Fatalf("shared object: %+v", got)
	}
}
