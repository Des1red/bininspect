package decoder

import (
	"bytes"
	"errors"
	"testing"

	"bininspect/internal/binary"
)

func testImage(
	t *testing.T,
	arch binary.Architecture,
	permissions binary.Permissions,
	code []byte,
) *binary.Image {
	t.Helper()

	bits := uint8(32)

	switch arch {
	case binary.ArchX8664,
		binary.ArchARM64,
		binary.ArchRISCV64:
		bits = 64
	}

	image, err := binary.NewImage(
		bytes.NewReader(code),
		uint64(len(code)),
		binary.Info{
			Format:       binary.FormatELF,
			Architecture: arch,
			Bits:         bits,
			Endianness:   binary.LittleEndian,
		},
		[]binary.Region{
			{
				Name:        ".text",
				Address:     0x401000,
				MemorySize:  uint64(len(code)),
				FileOffset:  0,
				FileSize:    uint64(len(code)),
				Permissions: permissions,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return image
}

func TestX8664Instructions(t *testing.T) {
	code := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0xe8, 5, 0, 0, 0, // call +5
		0x74, 2, // je +2
		0xc3,       // ret
		0x90,       // nop
		0xc3,       // ret
		0xff, 0xd0, // call rax
	}

	image := testImage(
		t,
		binary.ArchX8664,
		binary.PermRead|binary.PermExecute,
		code,
	)

	instructions, err := DecodeRange(
		image,
		0x401000,
		uint64(len(code)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(instructions) != 8 {
		t.Fatalf(
			"expected 8 instructions, got %d",
			len(instructions),
		)
	}

	call := instructions[2]

	if call.Flow != FlowCall ||
		!call.HasTarget ||
		call.Target != 0x40100e {
		t.Fatalf("wrong direct call: %+v", call)
	}

	branch := instructions[3]

	if branch.Flow != FlowConditional ||
		!branch.HasTarget ||
		branch.Target != 0x40100d {
		t.Fatalf("wrong conditional branch: %+v", branch)
	}

	if instructions[4].Flow != FlowReturn {
		t.Fatalf("RET not recognized")
	}

	indirect := instructions[7]

	if indirect.Flow != FlowCall ||
		!indirect.Indirect ||
		indirect.HasTarget ||
		indirect.Operands[0].Register != "RAX" {
		t.Fatalf("wrong indirect call: %+v", indirect)
	}
}

func TestX86MemoryOperand(t *testing.T) {
	image := testImage(
		t,
		binary.ArchX8664,
		binary.PermRead|binary.PermExecute,
		[]byte{0x48, 0x8b, 0x45, 0xf8},
	)

	instruction, err := DecodeAt(
		image,
		0x401000,
	)
	if err != nil {
		t.Fatal(err)
	}

	if instruction.Mnemonic != "MOV" ||
		len(instruction.Operands) != 2 {
		t.Fatalf("unexpected instruction: %+v", instruction)
	}

	memory := instruction.Operands[1]

	if memory.Kind != OperandMemory ||
		memory.Memory.Base != "RBP" ||
		memory.Memory.Displacement != -8 ||
		memory.Memory.SizeBytes != 8 {
		t.Fatalf("wrong memory operand: %+v", memory)
	}
}

func TestX8632RelativeBranch(t *testing.T) {
	image := testImage(
		t,
		binary.ArchX86,
		binary.PermRead|binary.PermExecute,
		[]byte{0x75, 0xfe},
	)

	instruction, err := DecodeAt(
		image,
		0x401000,
	)
	if err != nil {
		t.Fatal(err)
	}

	if instruction.Flow != FlowConditional ||
		!instruction.HasTarget ||
		instruction.Target != 0x401000 {
		t.Fatalf("wrong backward branch: %+v", instruction)
	}
}

func TestX86Breakpoint(t *testing.T) {
	for _, code := range [][]byte{
		{0xcc},
		{0xcd, 0x03},
	} {
		image := testImage(
			t,
			binary.ArchX8664,
			binary.PermRead|binary.PermExecute,
			code,
		)

		instruction, err := DecodeAt(
			image,
			0x401000,
		)
		if err != nil {
			t.Fatal(err)
		}

		if instruction.Flow != FlowTrap {
			t.Fatalf(
				"%x: expected breakpoint trap",
				code,
			)
		}
	}
}

func TestDecoderErrors(t *testing.T) {
	truncated := testImage(
		t,
		binary.ArchX8664,
		binary.PermRead|binary.PermExecute,
		[]byte{0xe8, 0, 0},
	)

	if _, err := DecodeAt(
		truncated,
		0x401000,
	); err == nil {
		t.Fatal("accepted incomplete CALL")
	}

	// The decoding range ends inside a valid instruction.
	valid := testImage(
		t,
		binary.ArchX8664,
		binary.PermRead|binary.PermExecute,
		[]byte{0x48, 0x89, 0xe5},
	)

	_, err := DecodeRange(
		valid,
		0x401000,
		2,
	)
	if !errors.Is(err, ErrTruncatedInstruction) {
		t.Fatalf("wrong range error: %v", err)
	}

	nonexecutable := testImage(
		t,
		binary.ArchX8664,
		binary.PermRead,
		[]byte{0x90},
	)

	_, err = DecodeAt(
		nonexecutable,
		0x401000,
	)
	if !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("accepted non-executable memory: %v", err)
	}

	unsupported := testImage(
		t,
		binary.ArchX86,
		binary.PermRead|binary.PermExecute,
		[]byte{0x90},
	)

	_, err = DecodeAtMode(
		unsupported,
		0x401000,
		ModeThumb,
	)

	if !errors.Is(err, ErrUnsupportedArchitecture) {
		t.Fatalf("accepted Thumb mode on x86: %v", err)
	}
}

func TestX86CETLandingPads(t *testing.T) {
	tests := []struct {
		name     string
		arch     binary.Architecture
		bytes    []byte
		mnemonic string
	}{
		{
			name:     "ENDBR64",
			arch:     binary.ArchX8664,
			bytes:    []byte{0xF3, 0x0F, 0x1E, 0xFA},
			mnemonic: "ENDBR64",
		},
		{
			name:     "ENDBR32",
			arch:     binary.ArchX86,
			bytes:    []byte{0xF3, 0x0F, 0x1E, 0xFB},
			mnemonic: "ENDBR32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := decodeX86(
				tt.bytes,
				0x1000,
				tt.arch,
			)
			if err != nil {
				t.Fatal(err)
			}

			if inst.Mnemonic != tt.mnemonic ||
				inst.Size != 4 ||
				inst.Flow != FlowNone {
				t.Fatalf("incorrect CET decode: %+v", inst)
			}
		})
	}
}
