package dataflow

import (
	"fmt"
	"strings"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

type state struct {
	regs  map[string]Value
	stack map[int64]Value
}

func newState() state {
	return state{
		regs:  map[string]Value{"rsp": {Kind: "stack-address"}},
		stack: make(map[int64]Value),
	}
}

func (s state) clone() state {
	out := state{
		regs:  make(map[string]Value, len(s.regs)),
		stack: make(map[int64]Value, len(s.stack)),
	}
	for k, v := range s.regs {
		out.regs[k] = v
	}
	for k, v := range s.stack {
		out.stack[k] = v
	}
	return out
}

// Must-join: a fact survives only if both paths agree exactly.
func (s *state) intersect(other state) bool {
	changed := false
	for k, v := range s.regs {
		if w, ok := other.regs[k]; !ok || w != v {
			delete(s.regs, k)
			changed = true
		}
	}
	for k, v := range s.stack {
		if w, ok := other.stack[k]; !ok || w != v {
			delete(s.stack, k)
			changed = true
		}
	}
	return changed
}

func canonicalRegister(raw string) string {
	r := strings.ToLower(raw)
	switch r {
	case "eax", "ax", "al", "ah":
		return "rax"
	case "ebx", "bx", "bl", "bh":
		return "rbx"
	case "ecx", "cx", "cl", "ch":
		return "rcx"
	case "edx", "dx", "dl", "dh":
		return "rdx"
	case "esi", "si", "sil":
		return "rsi"
	case "edi", "di", "dil":
		return "rdi"
	case "esp", "sp", "spl":
		return "rsp"
	case "ebp", "bp", "bpl":
		return "rbp"
	case "r8d", "r8w", "r8b":
		return "r8"
	case "r9d", "r9w", "r9b":
		return "r9"
	case "r10d", "r10w", "r10b":
		return "r10"
	case "r11d", "r11w", "r11b":
		return "r11"
	case "r12d", "r12w", "r12b":
		return "r12"
	case "r13d", "r13w", "r13b":
		return "r13"
	case "r14d", "r14w", "r14b":
		return "r14"
	case "r15d", "r15w", "r15b":
		return "r15"
	default:
		return r
	}
}

func is32Register(r string) bool {
	r = strings.ToLower(r)
	switch r {
	case "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp":
		return true
	}
	return strings.HasPrefix(r, "r") && strings.HasSuffix(r, "d") &&
		len(r) >= 3 && (r[1] >= '8' && r[1] <= '9' ||
		len(r) == 4 && r[1] == '1' && r[2] >= '0' && r[2] <= '5')
}

func isFullRegister(raw string, arch binary.Architecture) bool {
	r := strings.ToLower(raw)
	key := canonicalRegister(r)
	if arch == binary.ArchX86 {
		return is32Register(r)
	}
	return r == key
}

func (s state) stackAddress(
	op decoder.Operand,
) (int64, bool) {
	if op.Kind != decoder.OperandMemory ||
		op.Memory.Index != "" {
		return 0, false
	}

	base, ok := s.regs[canonicalRegister(op.Memory.Base)]

	if !ok || base.Kind != "stack-address" {
		return 0, false
	}

	disp := op.Memory.Displacement

	// An x86 disp32 is signed. Normalize values that
	// were represented as zero-extended 32-bit offsets.
	//
	// This conversion is limited to memory references
	// whose base is already known to be stack-relative.
	if disp >= 1<<31 &&
		disp <= (1<<32)-1 {
		disp = int64(int32(uint32(disp)))
	}

	return base.StackOffset + disp, true
}
func (s state) read(
	op decoder.Operand,
	arch binary.Architecture,
	word int64,
) Value {
	switch op.Kind {
	case decoder.OperandImmediate:
		return Value{Kind: "constant", Number: op.Immediate}

	case decoder.OperandRegister:
		v := s.regs[canonicalRegister(op.Register)]
		if !isFullRegister(op.Register, arch) {
			if arch == binary.ArchX8664 &&
				is32Register(op.Register) &&
				v.Kind == "constant" {
				v.Number = int64(uint32(v.Number))
			} else {
				return Value{}
			}
		}
		return v

	case decoder.OperandMemory:
		if int64(op.Memory.SizeBytes) != word {
			return Value{}
		}
		if offset, ok := s.stackAddress(op); ok {
			return s.stack[offset]
		}
	}
	return Value{}
}

func (s *state) write(
	op decoder.Operand,
	v Value,
	arch binary.Architecture,
	word int64,
) {
	switch op.Kind {
	case decoder.OperandRegister:
		key := canonicalRegister(op.Register)

		if !isFullRegister(op.Register, arch) {
			// In long mode a 32-bit write zero-extends.
			// Other partial writes destroy whole-register facts.
			if arch == binary.ArchX8664 &&
				is32Register(op.Register) &&
				v.Kind == "constant" {
				v.Number = int64(uint32(v.Number))
			} else {
				v = Value{}
			}
		}

		if v.Kind == "" {
			delete(s.regs, key)
		} else {
			s.regs[key] = v
		}

	case decoder.OperandMemory:
		if offset, ok := s.stackAddress(op); ok {
			// Every tracked slot represents a full machine word.
			// A partial store might invalidate an overlapping slot.
			if int64(op.Memory.SizeBytes) != word {
				s.stack = make(map[int64]Value)
				return
			}

			for addr := range s.stack {
				if addr != offset &&
					addr < offset+word &&
					offset < addr+word {
					delete(s.stack, addr)
				}
			}

			if v.Kind == "" {
				delete(s.stack, offset)
			} else {
				s.stack[offset] = v
			}
		} else {
			// Unknown pointer store may alias any tracked slot.
			s.stack = make(map[int64]Value)
		}
	}
}

func (s *state) step(
	inst decoder.Instruction,
	arch binary.Architecture,
	word int64,
) {
	args := inst.Operands
	op := strings.ToUpper(inst.Mnemonic)

	if inst.Flow != decoder.FlowNone {
		// Calls are handled by the caller.
		// Branches and returns do not modify tracked registers.
		if inst.Flow == decoder.FlowSystem {
			s.regs = map[string]Value{}
			s.stack = map[int64]Value{}
		}
		return
	}

	switch op {
	case "NOP", "ENDBR32", "ENDBR64",
		"CMP", "TEST", "CLD", "STD":
		return

	case "PUSH":
		sp := s.regs["rsp"]
		if sp.Kind != "stack-address" {
			delete(s.regs, "rsp")
			return
		}

		var v Value
		if len(args) > 0 {
			v = s.read(args[0], arch, word)
		}

		sp.StackOffset -= word
		s.regs["rsp"] = sp

		if v.Kind == "" {
			delete(s.stack, sp.StackOffset)
		} else {
			s.stack[sp.StackOffset] = v
		}

	case "POP":
		sp := s.regs["rsp"]
		if sp.Kind != "stack-address" {
			if len(args) > 0 {
				s.write(args[0], Value{}, arch, word)
			}
			return
		}

		v := s.stack[sp.StackOffset]
		delete(s.stack, sp.StackOffset)
		sp.StackOffset += word
		s.regs["rsp"] = sp

		if len(args) > 0 {
			s.write(args[0], v, arch, word)
		}

	case "LEAVE":
		bp := s.regs["rbp"]
		if bp.Kind != "stack-address" {
			delete(s.regs, "rsp")
			delete(s.regs, "rbp")
			return
		}

		s.regs["rsp"] = bp
		delete(s.stack, bp.StackOffset)
		delete(s.regs, "rbp")
		s.regs["rsp"] = Value{
			Kind:        "stack-address",
			StackOffset: bp.StackOffset + word,
		}

	case "MOV", "MOVABS", "MOVZX", "MOVSX", "MOVSXD":
		if len(args) == 2 {
			s.write(
				args[0],
				s.read(args[1], arch, word),
				arch, word,
			)
		}

	case "LEA":
		if len(args) == 2 {
			var v Value

			if offset, ok := s.stackAddress(args[1]); ok {
				v = Value{
					Kind:        "stack-address",
					StackOffset: offset,
				}
			}

			s.write(args[0], v, arch, word)
		}

	case "XOR":
		if len(args) == 2 {
			if args[0].Kind == decoder.OperandRegister &&
				args[1].Kind == decoder.OperandRegister &&
				strings.EqualFold(
					args[0].Register,
					args[1].Register,
				) {
				s.write(
					args[0],
					Value{Kind: "constant"},
					arch, word,
				)
			} else {
				s.write(args[0], Value{}, arch, word)
			}
		}

	case "SUB", "ADD":
		if len(args) != 2 {
			return
		}

		v := s.read(args[0], arch, word)
		amount := s.read(args[1], arch, word)

		if amount.Kind != "constant" {
			s.write(args[0], Value{}, arch, word)
			return
		}

		delta := amount.Number

		// ADD/SUB with a 32-bit immediate can encode a negative
		// displacement as an unsigned-looking value.
		//
		// Normalize only when operating on a tracked stack address;
		// do not reinterpret every constant in the analyzer.
		if v.Kind == "stack-address" &&
			args[1].Kind == decoder.OperandImmediate &&
			delta >= 1<<31 &&
			delta <= (1<<32)-1 {

			delta = int64(int32(uint32(delta)))
		}

		if op == "SUB" {
			delta = -delta
		}

		switch v.Kind {
		case "constant":
			v.Number += delta

		case "stack-address":
			v.StackOffset += delta

		default:
			v = Value{}
		}

		s.write(args[0], v, arch, word)

	case "AND":
		if len(args) > 0 {
			if args[0].Kind == decoder.OperandRegister &&
				canonicalRegister(args[0].Register) == "rsp" {
				// Stack alignment invalidates the coordinate system.
				s.regs = map[string]Value{}
				s.stack = map[int64]Value{}
			} else {
				s.write(args[0], Value{}, arch, word)
			}
		}

	default:
		// Unmodeled implicit effects may modify registers or memory.
		// Discard facts rather than making false assertions.
		s.regs = map[string]Value{}
		s.stack = map[int64]Value{}
	}
}

func arguments(
	s state,
	arch binary.Architecture,
) []Argument {
	if arch == binary.ArchX8664 {
		// System V AMD64: integer/pointer argument locations.
		regs := []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
		out := make([]Argument, 0, len(regs))

		for i, r := range regs {
			out = append(out, Argument{
				Position: i + 1,
				Location: r,
				Value:    s.regs[r],
			})
		}
		return out
	}

	out := make([]Argument, 0, 6)
	sp := s.regs["rsp"]

	for i := 0; i < 6; i++ {
		var v Value
		if sp.Kind == "stack-address" {
			v = s.stack[sp.StackOffset+int64(i*4)]
		}

		out = append(out, Argument{
			Position: i + 1,
			Location: fmt.Sprintf("[esp+%d]", i*4),
			Value:    v,
		})
	}
	return out
}

func (s *state) clobber(arch binary.Architecture) {
	regs := []string{"rax", "rcx", "rdx"}

	if arch == binary.ArchX8664 {
		regs = []string{
			"rax", "rcx", "rdx", "rdi",
			"rsi", "r8", "r9", "r10", "r11",
		}
	}

	for _, r := range regs {
		delete(s.regs, r)
	}

	// Calls may mutate memory reachable through escaped pointers.
	s.stack = map[int64]Value{}
}
