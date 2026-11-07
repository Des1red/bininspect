package binary

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func encodeSLEB(value int64) []byte {
	var result []byte

	for {
		part := byte(value & 0x7f)
		value >>= 7

		done := (value == 0 && part&0x40 == 0) ||
			(value == -1 && part&0x40 != 0)

		if !done {
			part |= 0x80
		}

		result = append(result, part)

		if done {
			return result
		}
	}
}

func packedFixture(values ...int64) []byte {
	result := []byte("APS2")

	for _, value := range values {
		result = append(result, encodeSLEB(value)...)
	}

	return result
}

func TestAndroidPackedGroups(t *testing.T) {
	data := packedFixture(
		4,
		0x4005f8,

		2, 3, 8, (1<<32)|7,

		2, 12, -2,
		8, (2<<32)|7,
		8, (1<<32)|7,
	)

	records, err := decodeAndroidAPS2(data, 64, true)
	if err != nil {
		t.Fatal(err)
	}

	expected := []uint64{
		0x400600,
		0x400608,
		0x400610,
		0x400618,
	}

	if len(records) != len(expected) {
		t.Fatalf("expected 4 relocations, got %d", len(records))
	}

	for i, record := range records {
		if record.Offset != expected[i] {
			t.Fatalf(
				"relocation %d: offset %#x, expected %#x",
				i, record.Offset, expected[i],
			)
		}

		if i >= 2 && record.Addend != -2 {
			t.Fatalf(
				"relocation %d: addend %d",
				i, record.Addend,
			)
		}
	}

	if records[0].SymbolIndex != 1 ||
		records[2].SymbolIndex != 2 ||
		records[3].SymbolIndex != 1 {
		t.Fatalf("incorrect symbol indices: %+v", records)
	}
}

func TestAndroidPackedELF32(t *testing.T) {
	data := packedFixture(
		2, 0x1000,
		2, 1, 8,
		4, 8,
	)

	records, err := decodeAndroidAPS2(data, 32, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(records) != 2 ||
		records[0].Offset != 0x1004 ||
		records[1].Offset != 0x100c ||
		records[0].Type != 8 ||
		records[0].HasAddend {
		t.Fatalf("incorrect ELF32 REL records: %+v", records)
	}
}

func TestAndroidPackedMalformed(t *testing.T) {
	cases := [][]byte{
		[]byte("BAD2"),
		packedFixture(-1, 0),
		packedFixture(2, 0, 3, 1),
		packedFixture(1, 0, 1, 4),
		packedFixture(1, 0, 1, 8, 4, 8),
		packedFixture(2, math.MaxInt64, 2, 2, math.MaxInt64),
		packedFixture(1, 0, 1, 0, 1),
		append(packedFixture(0, 0), 0),
	}

	for i, data := range cases {
		if _, err := decodeAndroidAPS2(
			data, 64, false,
		); err == nil {
			t.Fatalf(
				"accepted malformed packed relocation case %d",
				i,
			)
		}
	}
}

func TestAndroidLegacyRELR(t *testing.T) {
	var data [16]byte

	binary.LittleEndian.PutUint64(data[0:], 0x400600)
	binary.LittleEndian.PutUint64(data[8:], 0b1011)

	records, err := decodeAndroidRELR(
		data[:],
		64,
		binary.LittleEndian,
	)
	if err != nil {
		t.Fatal(err)
	}

	expected := []uint64{
		0x400600,
		0x400608,
		0x400618,
	}

	if len(records) != len(expected) {
		t.Fatalf(
			"expected %d RELR records, got %d",
			len(expected), len(records),
		)
	}

	for i, record := range records {
		if record.Offset != expected[i] {
			t.Fatalf(
				"RELR[%d]: %#x, expected %#x",
				i, record.Offset, expected[i],
			)
		}
	}
}

func TestAndroidPackedMetadataIntegration(t *testing.T) {
	raw := dynamicMetadataFixture()

	// Replace the old DT_NULL with Android packed RELA tags.
	const dynamicBase = 0x180
	const packedOffset = 0x560

	packed := packedFixture(
		2, 0x400630,
		2, 3, 8,
		(1<<32)|7,
	)

	copy(raw[packedOffset:], packed)

	bo := binary.LittleEndian

	bo.PutUint64(
		raw[dynamicBase+14*16:],
		uint64(dynAndroidRELA),
	)
	bo.PutUint64(
		raw[dynamicBase+14*16+8:],
		0x400560,
	)

	bo.PutUint64(
		raw[dynamicBase+15*16:],
		uint64(dynAndroidRELASZ),
	)
	bo.PutUint64(
		raw[dynamicBase+15*16+8:],
		uint64(len(packed)),
	)

	// Record 16 remains DT_NULL.
	bo.PutUint64(raw[120+32:], 17*16)
	bo.PutUint64(raw[120+40:], 17*16)

	result, err := ParseELFDynamicMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Relocations) != 7 {
		t.Fatalf(
			"expected 7 relocations, got %d",
			len(result.Relocations),
		)
	}

	for _, relocation := range result.Relocations {
		if relocation.Encoding != "ANDROID_RELA" {
			continue
		}

		if relocation.SymbolName != "puts" {
			t.Fatalf(
				"packed relocation symbol = %q",
				relocation.SymbolName,
			)
		}
	}
}

func TestAndroidPackedLLD(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang required for Android packed ELF corpus")
	}

	if _, err := exec.LookPath("ld.lld"); err != nil {
		t.Skip("ld.lld required for Android packed ELF corpus")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "packed.c")
	library := filepath.Join(dir, "libpacked.so")

	code := []byte(
		"extern int puts(const char *);\n" +
			"int counter = 4;\n" +
			"int *p0 = &counter;\n" +
			"int *p1 = &counter;\n" +
			"int *p2 = &counter;\n" +
			"int exported(void) {\n" +
			"  return puts(\"hello\") + *p0 + *p1 + *p2;\n" +
			"}\n",
	)

	if err := os.WriteFile(source, code, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		compiler,
		"-shared",
		"-fPIC",
		"-fuse-ld=lld",
		"-Wl,--pack-dyn-relocs=android",
		"-o", library,
		source,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf(
			"building packed library: %v\n%s",
			err, output,
		)
	}

	raw, err := os.ReadFile(library)
	if err != nil {
		t.Fatal(err)
	}

	sectionMetadata, err := ParseELFMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	dynamicMetadata, err := ParseELFDynamicMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	var packedSections, packedDynamic int

	for _, r := range sectionMetadata.Relocations {
		if r.Encoding == "ANDROID_RELA" {
			packedSections++
		}
	}

	for _, r := range dynamicMetadata.Relocations {
		if r.Encoding == "ANDROID_RELA" {
			packedDynamic++
		}
	}

	if packedSections == 0 ||
		packedSections != packedDynamic {
		t.Fatalf(
			"packed relocation mismatch: sections=%d dynamic=%d",
			packedSections,
			packedDynamic,
		)
	}

	validation, err := CrossValidateELF(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if validation.Mode != "dual-source" {
		t.Fatalf(
			"unexpected validation mode: %s",
			validation.Mode,
		)
	}

	sectionless := sectionlessELF(t, raw)

	recovered, err := ParseELFDynamicMetadata(
		bytes.NewReader(sectionless),
		uint64(len(sectionless)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(recovered.Relocations) != len(dynamicMetadata.Relocations) {
		t.Fatalf(
			"sectionless relocations: %d, original: %d",
			len(recovered.Relocations),
			len(dynamicMetadata.Relocations),
		)
	}
}
