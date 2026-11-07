package binary

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestImageMappingAndReads(t *testing.T) {
	raw := []byte{
		0xaa, 0xbb,
		0x55, 0x66, 0x77, 0x88,
		0xcc,
	}

	image, err := NewImage(
		bytes.NewReader(raw),
		uint64(len(raw)),
		Info{
			Format:       FormatELF,
			Architecture: ArchX86,
			Bits:         32,
			Endianness:   LittleEndian,
			Entry:        0x1000,
		},
		[]Region{{
			Name:        ".text",
			Address:     0x1000,
			MemorySize:  6,
			FileOffset:  2,
			FileSize:    4,
			Permissions: PermRead | PermExecute,
		}},
	)

	if err != nil {
		t.Fatal(err)
	}

	offset, err := image.VirtualToFile(0x1002)

	if err != nil || offset != 4 {
		t.Fatalf("offset=%d, err=%v", offset, err)
	}

	executable, err := image.ReadExecutable(0x1000, 4)

	if err != nil ||
		!reflect.DeepEqual(
			executable,
			[]byte{0x55, 0x66, 0x77, 0x88},
		) {
		t.Fatalf("bytes=%x, err=%v", executable, err)
	}

	memory, err := image.ReadMemory(0x1003, 3)

	if err != nil ||
		!reflect.DeepEqual(memory, []byte{0x88, 0, 0}) {
		t.Fatalf("memory=%x, err=%v", memory, err)
	}

	if _, err := image.ReadVirtual(0x1004, 1); !errors.Is(err, ErrNotFileBacked) {
		t.Fatalf("zero-fill error: %v", err)
	}

	if _, err := image.VirtualToFile(0x1004); !errors.Is(err, ErrNotFileBacked) {
		t.Fatalf("offset error: %v", err)
	}

	if _, err := image.ReadExecutable(0xfff, 1); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("unmapped error: %v", err)
	}

	if _, err := image.ReadMemory(0x1005, 2); !errors.Is(err, ErrRegionBoundary) {
		t.Fatalf("boundary error: %v", err)
	}

	if _, err := image.ReadVirtual(0x1000, MaxReadSize+1); err == nil {
		t.Fatal("missing read limit")
	}
}

func TestImageValidation(t *testing.T) {
	info := Info{
		Format:       FormatELF,
		Architecture: ArchX86,
		Bits:         32,
		Endianness:   LittleEndian,
	}

	raw := bytes.NewReader(make([]byte, 64))

	base := Region{
		Name:        "text",
		Address:     0x1000,
		MemorySize:  16,
		FileOffset:  8,
		FileSize:    8,
		Permissions: PermExecute,
	}

	tests := []struct {
		name    string
		regions []Region
	}{
		{"empty", nil},
		{"zero", []Region{{Name: "zero"}}},
		{"oversized backed range", []Region{{
			Name: "bad", Address: 1,
			MemorySize: 4, FileSize: 5,
		}}},
		{"virtual overflow", []Region{{
			Name:       "bad",
			Address:    math.MaxUint64 - 2,
			MemorySize: 4,
		}}},
		{"file overflow", []Region{{
			Name: "bad", Address: 1,
			MemorySize: 20, FileOffset: 60, FileSize: 8,
		}}},
		{"overlap", []Region{
			base,
			{Name: "other", Address: 0x100f, MemorySize: 4},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewImage(
				raw, 64, info, tt.regions,
			); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	image, err := NewImage(
		raw,
		64,
		info,
		[]Region{
			base,
			{
				Name:       "data",
				Address:    0x1100,
				MemorySize: 8,
				FileOffset: 16,
				FileSize:   8,
			},
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	got := image.Regions()
	got[0].Address = 0

	if image.Regions()[0].Address != 0x1000 {
		t.Fatal("caller modified image mappings")
	}

	if _, err := image.ReadExecutable(0x1100, 1); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("nonexec error: %v", err)
	}
}
