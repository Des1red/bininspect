package collect

import (
	"debug/elf"
	stdbinary "encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"bininspect/internal/binary"
)

func TestEngineELFPipeline(t *testing.T) {
	raw := make([]byte, 0x200)

	copy(raw[:4], "\x7fELF")
	raw[4], raw[5], raw[6] = 2, 1, 1
	bo := stdbinary.LittleEndian

	bo.PutUint16(raw[16:], uint16(elf.ET_EXEC))
	bo.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(raw[20:], 1)
	bo.PutUint64(raw[24:], 0x400100)
	bo.PutUint64(raw[32:], 64)

	bo.PutUint16(raw[52:], 64)
	bo.PutUint16(raw[54:], 56)
	bo.PutUint16(raw[56:], 1)

	p := raw[64:]

	bo.PutUint32(p[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(p[4:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint64(p[8:], 0x100)
	bo.PutUint64(p[16:], 0x400100)
	bo.PutUint64(p[32:], 4)
	bo.PutUint64(p[40:], 8)
	bo.PutUint64(p[48:], 0x100)

	// push rbp; mov ebp, esp; ret
	copy(raw[0x100:], []byte{
		0x55, 0x89, 0xe5, 0xc3,
	})

	path := filepath.Join(t.TempDir(), "test.elf")

	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	result, err := Engine(path)
	if err != nil {
		t.Fatal(err)
	}

	if result.Info.Format != binary.FormatELF ||
		result.ELFType != elf.ET_EXEC ||
		result.Structure.Programs != 1 ||
		result.Assembly.CandidateInstructions != 3 ||
		result.Assembly.Returns != 1 ||
		len(result.Graphs) != 1 {
		t.Fatalf("unexpected pipeline result: %+v", result)
	}
}

func TestEngineRejectsNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.bin")

	if err := os.WriteFile(
		path, []byte("not an ELF"), 0600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := Engine(path); err == nil {
		t.Fatal("accepted non-ELF input")
	}
}
