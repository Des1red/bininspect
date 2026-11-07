package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"reflect"
	"runtime"
	"testing"
)

func dynamicFixture() []byte {
	data := make([]byte, 0x300)

	copy(data[:4], "\x7fELF")
	data[4] = 2
	data[5] = 1
	data[6] = 1

	bo := binary.LittleEndian

	bo.PutUint16(data[16:], uint16(elf.ET_DYN))
	bo.PutUint16(data[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(data[20:], 1)
	bo.PutUint64(data[24:], 0x400100)
	bo.PutUint64(data[32:], 64)

	bo.PutUint16(data[52:], 64)
	bo.PutUint16(data[54:], 56)
	bo.PutUint16(data[56:], 2)

	load := data[64:]

	bo.PutUint32(load[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(load[4:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint64(load[8:], 0x100)
	bo.PutUint64(load[16:], 0x400100)
	bo.PutUint64(load[32:], 0x180)
	bo.PutUint64(load[40:], 0x180)
	bo.PutUint64(load[48:], 0x100)

	dynamic := data[64+56:]

	bo.PutUint32(dynamic[0:], uint32(elf.PT_DYNAMIC))
	bo.PutUint32(dynamic[4:], uint32(elf.PF_R))
	bo.PutUint64(dynamic[8:], 0x180)
	bo.PutUint64(dynamic[16:], 0x400180)
	bo.PutUint64(dynamic[32:], 16*6)
	bo.PutUint64(dynamic[40:], 16*6)
	bo.PutUint64(dynamic[48:], 8)

	copy(data[0x100:], []byte{0x90, 0x90, 0xc3})

	strtab := []byte(
		"\x00libfoo.so\x00libdemo.so\x00$ORIGIN/lib\x00",
	)
	copy(data[0x210:], strtab)

	tags := [][2]uint64{
		{uint64(elf.DT_NEEDED), 1},
		{uint64(elf.DT_STRTAB), 0x400210},
		{uint64(elf.DT_STRSZ), uint64(len(strtab))},
		{uint64(elf.DT_SONAME), 11},
		{uint64(elf.DT_RUNPATH), 22},
		{0, 0},
	}

	for i, entry := range tags {
		pos := 0x180 + i*16

		bo.PutUint64(data[pos:], entry[0])
		bo.PutUint64(data[pos+8:], entry[1])
	}

	return data
}

func TestDynamicSectionlessFixture(t *testing.T) {
	raw := dynamicFixture()

	result, err := ParseELFDynamic(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Present ||
		len(result.Entries) != 5 ||
		len(result.Needed) != 1 ||
		result.Needed[0] != "libfoo.so" ||
		result.SONAME != "libdemo.so" ||
		result.RUNPATH != "$ORIGIN/lib" {
		t.Fatalf("unexpected dynamic metadata: %+v", result)
	}
}

func dynamicFixture32(bo binary.ByteOrder) []byte {
	data := make([]byte, 0x300)

	copy(data[:4], "\x7fELF")
	data[4] = 1
	data[5] = 1

	if bo == binary.BigEndian {
		data[5] = 2
	}

	data[6] = 1

	bo.PutUint16(data[16:], uint16(elf.ET_DYN))

	machine := elf.EM_386
	if bo == binary.BigEndian {
		machine = elf.EM_ARM
	}

	bo.PutUint16(data[18:], uint16(machine))
	bo.PutUint32(data[20:], 1)
	bo.PutUint32(data[24:], 0x1000)
	bo.PutUint32(data[28:], 52)

	bo.PutUint16(data[40:], 52)
	bo.PutUint16(data[42:], 32)
	bo.PutUint16(data[44:], 2)

	load := data[52:]

	bo.PutUint32(load[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(load[4:], 0x100)
	bo.PutUint32(load[8:], 0x1000)
	bo.PutUint32(load[16:], 0x180)
	bo.PutUint32(load[20:], 0x180)
	bo.PutUint32(load[24:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint32(load[28:], 0x100)

	dynamic := data[84:]

	bo.PutUint32(dynamic[0:], uint32(elf.PT_DYNAMIC))
	bo.PutUint32(dynamic[4:], 0x180)
	bo.PutUint32(dynamic[8:], 0x1080)
	bo.PutUint32(dynamic[16:], 8*4)
	bo.PutUint32(dynamic[20:], 8*4)
	bo.PutUint32(dynamic[24:], uint32(elf.PF_R))
	bo.PutUint32(dynamic[28:], 4)

	strtab := []byte("\x00lib32.so\x00")
	copy(data[0x210:], strtab)

	tags := [][2]uint32{
		{uint32(elf.DT_NEEDED), 1},
		{uint32(elf.DT_STRTAB), 0x1110},
		{uint32(elf.DT_STRSZ), uint32(len(strtab))},
		{0, 0},
	}

	for i, entry := range tags {
		pos := 0x180 + i*8

		bo.PutUint32(data[pos:], entry[0])
		bo.PutUint32(data[pos+4:], entry[1])
	}

	return data
}

func TestDynamicELF32Endianness(t *testing.T) {
	for _, bo := range []binary.ByteOrder{
		binary.LittleEndian,
		binary.BigEndian,
	} {
		raw := dynamicFixture32(bo)

		result, err := ParseELFDynamic(
			bytes.NewReader(raw),
			uint64(len(raw)),
		)
		if err != nil {
			t.Fatal(err)
		}

		if !result.Present ||
			!reflect.DeepEqual(
				result.Needed,
				[]string{"lib32.so"},
			) {
			t.Fatalf("unexpected dynamic metadata: %+v", result)
		}
	}
}

func TestDynamicMalformed(t *testing.T) {
	tests := []struct {
		name   string
		modify func([]byte)
	}{
		{
			"invalid-needed-index",
			func(b []byte) {
				binary.LittleEndian.PutUint64(
					b[0x180+8:], 999,
				)
			},
		},
		{
			"mismatched-file-offset",
			func(b []byte) {
				binary.LittleEndian.PutUint64(
					b[64+56+8:], 0x190,
				)
			},
		},
		{
			"missing-terminator",
			func(b []byte) {
				binary.LittleEndian.PutUint64(
					b[0x180+5*16:], 42,
				)
			},
		},
		{
			"missing-string-table",
			func(b []byte) {
				binary.LittleEndian.PutUint64(
					b[0x180+16:], 43,
				)
			},
		},
		{
			"oversized-string-table",
			func(b []byte) {
				binary.LittleEndian.PutUint64(
					b[0x180+2*16+8:],
					MaxReadSize+1,
				)
			},
		},
		{
			"unterminated-string",
			func(b []byte) {
				b[0x210+len(
					"\x00libfoo.so\x00libdemo.so\x00$ORIGIN/lib\x00",
				)-1] = 'X'
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := dynamicFixture()
			tt.modify(raw)

			_, err := ParseELFDynamic(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)

			if err == nil {
				t.Fatal("accepted malformed dynamic metadata")
			}
		})
	}
}

func TestDynamicRealAndSectionless(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux ELF executable")
	}

	raw, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Skip(err)
	}

	original, err := ParseELFDynamic(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !original.Present || len(original.Needed) == 0 {
		t.Fatal("expected dynamic dependencies")
	}

	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Remove only ELF section-header references.
	// Program headers and loadable bytes remain unchanged.
	sectionless := append([]byte(nil), raw...)

	if file.Class == elf.ELFCLASS64 {
		for _, bounds := range [][2]int{
			{40, 48}, {60, 62}, {62, 64},
		} {
			for i := bounds[0]; i < bounds[1]; i++ {
				sectionless[i] = 0
			}
		}
	} else {
		for _, bounds := range [][2]int{
			{32, 36}, {48, 50}, {50, 52},
		} {
			for i := bounds[0]; i < bounds[1]; i++ {
				sectionless[i] = 0
			}
		}
	}

	result, err := ParseELFDynamic(
		bytes.NewReader(sectionless),
		uint64(len(sectionless)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(
		original.Needed,
		result.Needed,
	) {
		t.Fatalf(
			"dynamic dependencies changed: %v -> %v",
			original.Needed,
			result.Needed,
		)
	}
}
