package binary

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func objectFixture(class elf.Class) []byte {
	out := make([]byte, 0x320)

	copy(out[:4], "\x7fELF")
	out[4] = byte(class)
	out[5] = byte(elf.ELFDATA2LSB)
	out[6] = 1

	bo := binary.LittleEndian
	bo.PutUint16(out[16:], uint16(elf.ET_REL))

	if class == elf.ELFCLASS64 {
		bo.PutUint16(out[18:], uint16(elf.EM_X86_64))
		bo.PutUint32(out[20:], 1)
		bo.PutUint64(out[40:], 0x180)
		bo.PutUint16(out[52:], 64)
		bo.PutUint16(out[58:], 64)
		bo.PutUint16(out[60:], 5)
		bo.PutUint16(out[62:], 4)
	} else {
		bo.PutUint16(out[18:], uint16(elf.EM_386))
		bo.PutUint32(out[20:], 1)
		bo.PutUint32(out[32:], 0x180)
		bo.PutUint16(out[40:], 52)
		bo.PutUint16(out[46:], 40)
		bo.PutUint16(out[48:], 5)
		bo.PutUint16(out[50:], 4)
	}

	copy(out[0x100:], []byte{0x55, 0x89, 0xe5, 0xc3})
	copy(out[0x110:], []byte{1, 2, 3})

	names := []byte("\x00.text\x00.data\x00.bss\x00.shstrtab\x00")
	copy(out[0x120:], names)

	for idx := 1; idx < 5; idx++ {
		var off int

		if class == elf.ELFCLASS64 {
			off = 0x180 + idx*64
		} else {
			off = 0x180 + idx*40
		}

		s := out[off:]

		var name, typ, flags uint32
		var fileOff, size uint64

		switch idx {
		case 1:
			name = 1
			typ = uint32(elf.SHT_PROGBITS)
			flags = uint32(elf.SHF_ALLOC | elf.SHF_EXECINSTR)
			fileOff = 0x100
			size = 4

		case 2:
			name = 7
			typ = uint32(elf.SHT_PROGBITS)
			flags = uint32(elf.SHF_ALLOC | elf.SHF_WRITE)
			fileOff = 0x110
			size = 3

		case 3:
			name = 13
			typ = uint32(elf.SHT_NOBITS)
			flags = uint32(elf.SHF_ALLOC | elf.SHF_WRITE)
			fileOff = 0x400
			size = 8

		case 4:
			name = 18
			typ = uint32(elf.SHT_STRTAB)
			fileOff = 0x120
			size = uint64(len(names))
		}

		bo.PutUint32(s[0:], name)
		bo.PutUint32(s[4:], typ)

		if class == elf.ELFCLASS64 {
			bo.PutUint64(s[8:], uint64(flags))
			bo.PutUint64(s[24:], fileOff)
			bo.PutUint64(s[32:], size)
			bo.PutUint64(s[48:], 1)
		} else {
			bo.PutUint32(s[8:], flags)
			bo.PutUint32(s[16:], uint32(fileOff))
			bo.PutUint32(s[20:], uint32(size))
			bo.PutUint32(s[32:], 1)
		}
	}

	return out
}

func TestParseELFObjectSections(t *testing.T) {
	for _, class := range []elf.Class{
		elf.ELFCLASS32,
		elf.ELFCLASS64,
	} {
		t.Run(class.String(), func(t *testing.T) {
			raw := objectFixture(class)

			obj, err := ParseELFObject(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			sections := obj.Sections()

			if len(sections) != 5 ||
				sections[1].Name != ".text" ||
				sections[3].Name != ".bss" {
				t.Fatalf("unexpected sections: %+v", sections)
			}

			code, err := obj.ReadSection(1, 0, 4)
			if err != nil ||
				!bytes.Equal(
					code,
					[]byte{0x55, 0x89, 0xe5, 0xc3},
				) {
				t.Fatalf("code=%x err=%v", code, err)
			}

			zero, err := obj.ReadSection(3, 1, 5)
			if err != nil ||
				!bytes.Equal(zero, make([]byte, 5)) {
				t.Fatalf("bss=%x err=%v", zero, err)
			}

			offset, err := obj.SectionFileOffset(1, 2)
			if err != nil || offset != 0x102 {
				t.Fatalf("offset=%x err=%v", offset, err)
			}

			if _, err := obj.SectionFileOffset(3, 0); !errors.Is(
				err,
				ErrNotFileBacked,
			) {
				t.Fatalf("expected non-file-backed section: %v", err)
			}

			if _, err := obj.ReadSection(1, 3, 2); !errors.Is(
				err,
				ErrRegionBoundary,
			) {
				t.Fatalf("expected section boundary error: %v", err)
			}

			if _, err := obj.ReadSection(0, 0, 1); !errors.Is(
				err,
				ErrInvalidELFSection,
			) {
				t.Fatalf("expected invalid section index: %v", err)
			}

			sections[1].Name = "modified"

			if obj.Sections()[1].Name != ".text" {
				t.Fatal("caller modified object metadata")
			}
		})
	}
}

func TestParseELFObjectValidation(t *testing.T) {
	tests := []struct {
		name  string
		alter func([]byte)
	}{
		{
			"section-outside-file",
			func(raw []byte) {
				binary.LittleEndian.PutUint64(
					raw[0x180+64+24:],
					0x500,
				)
			},
		},
		{
			"bad-alignment",
			func(raw []byte) {
				binary.LittleEndian.PutUint64(
					raw[0x180+64+48:],
					3,
				)
			},
		},
		{
			"bad-type",
			func(raw []byte) {
				binary.LittleEndian.PutUint16(
					raw[16:],
					uint16(elf.ET_EXEC),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := objectFixture(elf.ELFCLASS64)
			tt.alter(raw)

			_, err := ParseELFObject(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)

			if err == nil {
				t.Fatal("accepted invalid object")
			}
		})
	}
}

func TestParseELFObjectCompressedSection(t *testing.T) {
	original := []byte("DWARF DEBUG DATA")

	var compressed bytes.Buffer

	writer := zlib.NewWriter(&compressed)

	if _, err := writer.Write(original); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	contents := make([]byte, 24+compressed.Len())

	binary.LittleEndian.PutUint32(
		contents[0:],
		uint32(elf.COMPRESS_ZLIB),
	)
	binary.LittleEndian.PutUint64(
		contents[8:],
		uint64(len(original)),
	)
	binary.LittleEndian.PutUint64(contents[16:], 1)

	copy(contents[24:], compressed.Bytes())

	raw := append(
		objectFixture(elf.ELFCLASS64),
		make([]byte, 0x150)...,
	)

	copy(raw[0x350:], contents)

	section := raw[0x180+2*64:]

	binary.LittleEndian.PutUint64(
		section[8:],
		uint64(elf.SHF_COMPRESSED),
	)
	binary.LittleEndian.PutUint64(section[24:], 0x350)
	binary.LittleEndian.PutUint64(
		section[32:],
		uint64(len(contents)),
	)

	obj, err := ParseELFObject(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	meta := obj.Sections()[2]

	if !meta.Compressed ||
		meta.Size != uint64(len(original)) {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	got, err := obj.ReadSection(
		2,
		0,
		uint64(len(original)),
	)

	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("decompressed=%q err=%v", got, err)
	}

	if _, err := obj.SectionFileOffset(2, 0); !errors.Is(
		err,
		ErrCompressedELFSection,
	) {
		t.Fatalf("expected compressed mapping error: %v", err)
	}
}

func TestParseELFObjectFromCompiler(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "sample.c")
	output := filepath.Join(dir, "sample.o")

	code := []byte(
		"int counter; int increment(int x) { return x+1; }",
	)

	if err := os.WriteFile(source, code, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(cc, "-c", "-o", output, source)

	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}

	obj, err := ParseELFObject(
		file,
		uint64(stat.Size()),
	)
	if err != nil {
		t.Fatal(err)
	}

	var foundExecutable bool

	for _, section := range obj.Sections() {
		if section.Flags&elf.SHF_EXECINSTR == 0 ||
			section.Size == 0 {
			continue
		}

		data, err := obj.ReadSection(
			section.Index,
			0,
			1,
		)

		if err != nil || len(data) != 1 {
			t.Fatalf(
				"reading executable section %q: %v",
				section.Name,
				err,
			)
		}

		foundExecutable = true
	}

	if !foundExecutable {
		t.Fatal("no executable sections discovered")
	}
}
