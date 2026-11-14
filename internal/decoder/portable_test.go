package decoder

import (
	"testing"

	"bininspect/internal/binary"
)

func TestPortableARM(t *testing.T) {
	// mov r0, #1; bx lr
	code := []byte{
		0x01, 0x00, 0xa0, 0xe3,
		0x1e, 0xff, 0x2f, 0xe1,
	}

	image := testImage(
		t,
		binary.ArchARM,
		binary.PermRead|binary.PermExecute,
		code,
	)

	ins, err := DecodeRangeMode(
		image, 0x401000, uint64(len(code)), ModeARM,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ins) != 2 ||
		ins[0].Mnemonic != "MOV" ||
		ins[1].Flow != FlowReturn {
		t.Fatalf("ARM decoding failed: %+v", ins)
	}
}

func TestPortableThumb(t *testing.T) {
	// nop; bx lr
	code := []byte{
		0x00, 0xbf,
		0x70, 0x47,
	}

	image := testImage(
		t,
		binary.ArchARM,
		binary.PermRead|binary.PermExecute,
		code,
	)

	ins, err := DecodeRangeMode(
		image, 0x401000, uint64(len(code)), ModeThumb,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ins) != 2 ||
		ins[0].Size != 2 ||
		ins[1].Size != 2 ||
		ins[1].Flow != FlowReturn {
		t.Fatalf("Thumb decoding failed: %+v", ins)
	}
}

func TestPortableThumbIT(t *testing.T) {
	// it eq; moveq r0, #1; bx lr
	code := []byte{
		0x08, 0xbf,
		0x01, 0x20,
		0x70, 0x47,
	}

	image := testImage(
		t,
		binary.ArchARM,
		binary.PermRead|binary.PermExecute,
		code,
	)

	ins, err := DecodeRangeMode(
		image, 0x401000, uint64(len(code)), ModeThumb,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ins) != 3 ||
		ins[0].Mode != ModeThumb ||
		ins[1].Mode != ModeThumb ||
		ins[2].Flow != FlowReturn {
		t.Fatalf("Thumb IT decoding failed: %+v", ins)
	}
}

func TestPortableThumb32(t *testing.T) {
	// 32-bit Thumb BL
	code := []byte{
		0x00, 0xf0,
		0x00, 0xf8,
	}

	inst, err := decodeThumb(
		code, 0x401000, binary.LittleEndian,
	)
	if err != nil {
		t.Fatal(err)
	}

	if inst.Size != 4 ||
		inst.Flow != FlowCall ||
		!inst.HasTarget {
		t.Fatalf("Thumb-2 BL failed: %+v", inst)
	}
}

func TestPortableARM64(t *testing.T) {
	// bl +8; ret; ret
	code := []byte{
		0x02, 0x00, 0x00, 0x94,
		0xc0, 0x03, 0x5f, 0xd6,
		0xc0, 0x03, 0x5f, 0xd6,
	}

	image := testImage(
		t,
		binary.ArchARM64,
		binary.PermRead|binary.PermExecute,
		code,
	)

	ins, err := DecodeRange(
		image, 0x401000, uint64(len(code)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ins) != 3 ||
		ins[0].Flow != FlowCall ||
		!ins[0].HasTarget ||
		ins[0].Target != 0x401008 ||
		ins[1].Flow != FlowReturn {
		t.Fatalf("ARM64 decoding failed: %+v", ins)
	}
}

func TestPortableARM64Memory(t *testing.T) {
	// ldr x0, [x1, #8]
	code := []byte{
		0x20, 0x04, 0x40, 0xf9,
	}

	image := testImage(
		t,
		binary.ArchARM64,
		binary.PermRead|binary.PermExecute,
		code,
	)

	inst, err := DecodeAt(image, 0x401000)
	if err != nil {
		t.Fatal(err)
	}

	if len(inst.Operands) != 2 {
		t.Fatalf("unexpected operands: %+v", inst)
	}

	mem := inst.Operands[1]

	if mem.Kind != OperandMemory ||
		mem.Memory.Base != "X1" ||
		mem.Memory.Displacement != 8 {
		t.Fatalf("ARM64 memory decoding failed: %+v", mem)
	}
}

func TestPortableRISCV64(t *testing.T) {
	// c.nop; addi x0,x0,0; jalr x0,0(x1)
	code := []byte{
		0x01, 0x00,
		0x13, 0x00, 0x00, 0x00,
		0x67, 0x80, 0x00, 0x00,
	}

	image := testImage(
		t,
		binary.ArchRISCV64,
		binary.PermRead|binary.PermExecute,
		code,
	)

	ins, err := DecodeRange(
		image, 0x401000, uint64(len(code)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ins) != 3 ||
		ins[0].Size != 2 ||
		ins[1].Size != 4 ||
		ins[2].Flow != FlowReturn {
		t.Fatalf("RISC-V decoding failed: %+v", ins)
	}
}
