package binary

import (
	"bytes"
	"debug/elf"
	"testing"
)

func TestEngineELFExecutable(t *testing.T) {
	for _, typ := range []elf.Type{
		elf.ET_EXEC,
		elf.ET_DYN,
	} {
		raw := elfFixture(
			elf.ELFCLASS64,
			elf.ELFDATA2LSB,
			elf.EM_X86_64,
		)

		// e_type in the ELF64 little-endian header.
		raw[16] = byte(typ)

		result, err := Engine(
			bytes.NewReader(raw),
			uint64(len(raw)),
		)
		if err != nil {
			t.Fatal(err)
		}

		if result.Image == nil ||
			result.Object != nil ||
			result.Info.Architecture != ArchX8664 ||
			len(result.Programs) != 1 {
			t.Fatalf(
				"invalid parsed executable: %+v",
				result,
			)
		}
	}
}

func TestEngineELFObject(t *testing.T) {
	raw := objectFixture(elf.ELFCLASS64)

	result, err := Engine(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Object == nil ||
		result.Image != nil ||
		len(result.Sections) < 2 ||
		result.Validation.Mode != "section-only" {
		t.Fatalf(
			"unexpected object: %+v", result,
		)
	}
}

func TestEngineELFDynamic(t *testing.T) {
	raw := dynamicMetadataFixture()

	result, err := Engine(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Image == nil ||
		!result.Dynamic.Present ||
		len(result.DynamicMetadata.Symbols) != 3 ||
		len(result.DynamicMetadata.Relocations) != 5 ||
		result.Validation.Mode != "dynamic-only" {
		t.Fatalf(
			"missing dynamic metadata: %+v",
			result,
		)
	}
}

func TestEngineRejectsInvalidReader(t *testing.T) {
	if _, err := Engine(nil, 1); err == nil {
		t.Fatal("accepted nil reader")
	}

	if _, err := Engine(
		bytes.NewReader([]byte("junk")),
		4,
	); err == nil {
		t.Fatal("accepted non-ELF")
	}
}
