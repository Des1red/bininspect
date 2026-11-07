package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// elfFixture creates a minimal ELF image with a four-byte
// executable region followed by four zero-filled bytes.
func elfFixture(class elf.Class, data elf.Data, machine elf.Machine) []byte {
	raw := make([]byte, 0x200)

	copy(raw[:4], "\x7fELF")
	raw[4] = byte(class)
	raw[5] = byte(data)
	raw[6] = byte(elf.EV_CURRENT)

	var bo binary.ByteOrder = binary.LittleEndian
	if data == elf.ELFDATA2MSB {
		bo = binary.BigEndian
	}

	bo.PutUint16(raw[16:], uint16(elf.ET_EXEC))
	bo.PutUint16(raw[18:], uint16(machine))
	bo.PutUint32(raw[20:], uint32(elf.EV_CURRENT))

	if class == elf.ELFCLASS32 {
		bo.PutUint32(raw[24:], 0x1000)
		bo.PutUint32(raw[28:], 52)
		bo.PutUint16(raw[40:], 52)
		bo.PutUint16(raw[42:], 32)
		bo.PutUint16(raw[44:], 1)

		p := raw[52:]
		bo.PutUint32(p[0:], uint32(elf.PT_LOAD))
		bo.PutUint32(p[4:], 0x100)
		bo.PutUint32(p[8:], 0x1000)
		bo.PutUint32(p[16:], 4)
		bo.PutUint32(p[20:], 8)
		bo.PutUint32(p[24:], uint32(elf.PF_R|elf.PF_X))
		bo.PutUint32(p[28:], 0x100)
	} else {
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
	}

	copy(raw[0x100:], []byte{0x55, 0x89, 0xe5, 0xc3})
	return raw
}

func TestParseELF32(t *testing.T) {
	raw := elfFixture(
		elf.ELFCLASS32,
		elf.ELFDATA2LSB,
		elf.EM_386,
	)

	image, err := ParseELF(bytes.NewReader(raw), uint64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}

	if image.Info.Format != FormatELF ||
		image.Info.Architecture != ArchX86 ||
		image.Info.Bits != 32 ||
		image.Info.Entry != 0x1000 {
		t.Fatalf("unexpected ELF32 metadata: %+v", image.Info)
	}

	regions := image.Regions()

	if len(regions) != 1 ||
		regions[0].Permissions != PermRead|PermExecute ||
		regions[0].MemorySize != 8 ||
		regions[0].FileSize != 4 {
		t.Fatalf("unexpected ELF32 segments: %+v", regions)
	}

	offset, err := image.VirtualToFile(0x1002)
	if err != nil || offset != 0x102 {
		t.Fatalf("offset=%#x err=%v", offset, err)
	}

	code, err := image.ReadExecutable(0x1000, 4)
	if err != nil ||
		!bytes.Equal(code, []byte{0x55, 0x89, 0xe5, 0xc3}) {
		t.Fatalf("code=%x err=%v", code, err)
	}

	memory, err := image.ReadMemory(0x1002, 6)
	if err != nil ||
		!bytes.Equal(memory, []byte{0xe5, 0xc3, 0, 0, 0, 0}) {
		t.Fatalf("memory=%x err=%v", memory, err)
	}

	if _, err := image.ReadExecutable(0x1004, 1); !errors.Is(
		err, ErrNotFileBacked,
	) {
		t.Fatalf("expected zero-fill read rejection: %v", err)
	}
}

func TestParseELF64AndBigEndian(t *testing.T) {
	tests := []struct {
		name    string
		class   elf.Class
		data    elf.Data
		machine elf.Machine
		arch    Architecture
		bits    uint8
		endian  Endianness
	}{
		{
			"amd64", elf.ELFCLASS64, elf.ELFDATA2LSB,
			elf.EM_X86_64, ArchX8664, 64, LittleEndian,
		},
		{
			"arm-big-endian", elf.ELFCLASS32, elf.ELFDATA2MSB,
			elf.EM_ARM, ArchARM, 32, BigEndian,
		},
		{
			"aarch64", elf.ELFCLASS64, elf.ELFDATA2LSB,
			elf.EM_AARCH64, ArchARM64, 64, LittleEndian,
		},
		{
			"riscv64", elf.ELFCLASS64, elf.ELFDATA2LSB,
			elf.EM_RISCV, ArchRISCV64, 64, LittleEndian,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := elfFixture(tt.class, tt.data, tt.machine)

			image, err := ParseELF(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if image.Info.Architecture != tt.arch ||
				image.Info.Bits != tt.bits ||
				image.Info.Endianness != tt.endian {
				t.Fatalf(
					"unexpected metadata: %+v",
					image.Info,
				)
			}

			regions := image.Regions()
			if len(regions) != 1 ||
				regions[0].FileOffset != 0x100 {
				t.Fatalf("unexpected regions: %+v", regions)
			}
		})
	}
}

func TestParseELFSharedObject(t *testing.T) {
	raw := elfFixture(
		elf.ELFCLASS64,
		elf.ELFDATA2LSB,
		elf.EM_X86_64,
	)

	binary.LittleEndian.PutUint16(
		raw[16:],
		uint16(elf.ET_DYN),
	)
	binary.LittleEndian.PutUint64(raw[24:], 0)

	if _, err := ParseELF(
		bytes.NewReader(raw),
		uint64(len(raw)),
	); err != nil {
		t.Fatal(err)
	}
}

func TestParseELFRejectsInvalidInputs(t *testing.T) {
	valid := elfFixture(
		elf.ELFCLASS64,
		elf.ELFDATA2LSB,
		elf.EM_X86_64,
	)

	tests := []struct {
		name     string
		change   func([]byte)
		want     error
		contains string
	}{
		{
			"invalid magic",
			func(p []byte) { p[0] = 0 },
			nil,
			"invalid ELF magic",
		},
		{
			"invalid machine",
			func(p []byte) {
				binary.LittleEndian.PutUint16(p[18:], 0xffff)
			},
			ErrUnsupportedELFMachine,
			"",
		},
		{
			"relocatable",
			func(p []byte) {
				binary.LittleEndian.PutUint16(
					p[16:], uint16(elf.ET_REL),
				)
			},
			ErrUnsupportedELFType,
			"",
		},
		{
			"extended program header count",
			func(p []byte) {
				binary.LittleEndian.PutUint16(p[56:], 0xffff)
			},
			ErrInvalidELFExtendedNumbering,
			"",
		},
		{
			"invalid program offset",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[32:], 0x1ff)
			},
			nil,
			"program header table extends beyond file",
		},
		{
			"oversized program count",
			func(p []byte) {
				binary.LittleEndian.PutUint16(p[56:], 100)
			},
			nil,
			"program header table extends beyond file",
		},
		{
			"oversized header size",
			func(p []byte) {
				binary.LittleEndian.PutUint16(p[52:], 0)
			},
			nil,
			"invalid ELF header size",
		},
		{
			"zero section table offset",
			func(p []byte) {
				binary.LittleEndian.PutUint16(p[60:], 1)
			},
			nil,
			"section header table absent but count or name index is present",
		},
		{
			"non-power-of-two alignment",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[64+48:], 3)
			},
			nil,
			"not a power of two",
		},
		{
			"bad segment alignment",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[64+16:], 0x400200)
				binary.LittleEndian.PutUint64(p[64+48:], 0x1000)
			},
			nil,
			"disagree modulo alignment",
		},
		{
			"segment extends beyond file",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[64+8:], 0x200)
			},
			nil,
			"extends past end of file",
		},
		{
			"filesz exceeds memsz",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[64+32:], 16)
			},
			nil,
			"maps more file bytes than virtual bytes",
		},
		{
			"entry outside executable",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[24:], 0x200000)
			},
			nil,
			"not in a file-backed executable segment",
		},
		{
			"unexecutable entry",
			func(p []byte) {
				binary.LittleEndian.PutUint32(
					p[64+4:], uint32(elf.PF_R),
				)
			},
			nil,
			"not in a file-backed executable segment",
		},
		{
			"non-load segment",
			func(p []byte) {
				binary.LittleEndian.PutUint32(
					p[64:], uint32(elf.PT_NOTE),
				)
			},
			nil,
			"no loadable regions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			tt.change(data)

			_, err := ParseELF(
				bytes.NewReader(data),
				uint64(len(data)),
			)

			if err == nil {
				t.Fatal("expected validation error")
			}

			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf(
					"expected %v, got %v",
					tt.want, err,
				)
			}

			if tt.contains != "" &&
				!strings.Contains(err.Error(), tt.contains) {
				t.Fatalf(
					"expected %q in error: %v",
					tt.contains, err,
				)
			}
		})
	}
}

func TestParseELFTruncated(t *testing.T) {
	raw := elfFixture(
		elf.ELFCLASS32,
		elf.ELFDATA2LSB,
		elf.EM_386,
	)

	for _, size := range []int{0, 4, 16, 51, 52, 0xff} {
		_, err := ParseELF(
			bytes.NewReader(raw[:size]),
			uint64(size),
		)

		if err == nil {
			t.Errorf("truncated ELF of size %d was accepted", size)
		}
	}
}

func TestParseELFRealExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}

	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}

	image, err := ParseELF(file, uint64(stat.Size()))
	if err != nil {
		t.Fatal(err)
	}

	if image.Info.Format != FormatELF ||
		len(image.Regions()) == 0 {
		t.Fatalf("unexpected image: %+v", image.Info)
	}

	code, err := image.ReadExecutable(image.Info.Entry, 1)
	if err != nil || len(code) != 1 {
		t.Fatalf("entry-point read: %x, %v", code, err)
	}
}

func TestParseELFExercises(t *testing.T) {
	root := os.Getenv("BININSPECT_ELF_CORPUS")
	if root == "" {
		t.Skip("set BININSPECT_ELF_CORPUS to hole-in-bin directory")
	}

	for _, exercise := range []string{"ex00", "ex01"} {
		t.Run(exercise, func(t *testing.T) {
			path := filepath.Join(root, exercise, "bin")

			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}

			image, err := ParseELF(
				file,
				uint64(stat.Size()),
			)
			if err != nil {
				t.Fatal(err)
			}

			if image.Info.Format != FormatELF ||
				image.Info.Architecture != ArchX86 ||
				image.Info.Bits != 32 {
				t.Fatalf(
					"unexpected exercise binary: %+v",
					image.Info,
				)
			}

			if _, err := image.ReadExecutable(
				image.Info.Entry, 1,
			); err != nil {
				t.Fatalf("entry point: %v", err)
			}
		})
	}
}
