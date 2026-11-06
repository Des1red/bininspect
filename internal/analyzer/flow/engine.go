package flow

import (
	"strings"

	"bininspect/internal/models"
)

type state struct {
	sp, bp, word int64
	pc           string
	bpOK         bool

	regs    map[string]value
	mem     map[int64]value
	zeroes  map[int64]bool
	inputs  []sink
	pending *comparison
}

type sink struct {
	api, call, ref, source string
	offset                 int64
	maxBytes               int64
}

type comparison struct {
	offset           int64
	ref, read, value string
}

type Result struct {
	Calls     []models.CallFlow
	Relations []models.StackRelation
}

func newState(word int64) *state {
	return &state{
		word:   word,
		regs:   map[string]value{},
		mem:    map[int64]value{},
		zeroes: map[int64]bool{},
	}
}

func Analyze(a models.AssemblyAnalysis, format string) Result {
	var result Result

	arch := strings.ToLower(a.Architecture)

	if !(strings.Contains(arch, "80386") ||
		strings.Contains(arch, "i386") ||
		strings.Contains(arch, "x86") ||
		strings.Contains(arch, "amd64")) {
		return result
	}

	word := int64(4)

	if strings.Contains(arch, "64") ||
		strings.Contains(arch, "amd64") {
		word = 8
	}

	var current string
	s := newState(word)

	for _, inst := range a.Instructions {
		if inst.Function != current {
			current = inst.Function
			s = newState(word)
		}

		s.step(inst, format, &result)
	}

	return result
}

func (s *state) step(
	in models.Instruction,
	format string,
	out *Result,
) {
	s.pc = in.Address

	op := strings.ToLower(in.Mnemonic)
	args := splitArgs(in.Operands)

	// Only preserve a comparison for an adjacent branch.
	if op != "cmp" && op != "test" &&
		!(strings.HasPrefix(op, "j") && op != "jmp") {
		s.pending = nil
	}

	switch op {
	case "push", "pushq", "pushl":
		v := s.read(in.Operands)
		s.sp -= s.word
		s.mem[s.sp] = v

	case "pop", "popq", "popl":
		v, exists := s.mem[s.sp]
		if !exists {
			v = value{}
		}

		delete(s.mem, s.sp)
		s.sp += s.word
		s.write(in.Operands, v)

	case "mov", "movzx", "movsx", "movsxd", "movabs":
		if len(args) != 2 {
			return
		}

		s.write(args[0], s.read(args[1]))

	case "lea":
		if len(args) != 2 {
			return
		}

		m, ok := s.address(args[1])
		if !ok {
			return
		}

		if m.stack {
			s.write(args[0], value{
				kind:   "stackaddr",
				offset: m.offset,
				ref:    m.expression,
			})
		} else {
			s.write(args[0], value{
				kind: "symbolic",
				expr: "&" + m.expression,
			})
		}

	case "sub", "add":
		if len(args) != 2 {
			return
		}

		v := s.read(args[0])
		n, ok := number(args[1])

		if !ok {
			s.write(args[0], value{})
			return
		}

		if op == "sub" {
			n = -n
		}

		if r := reg(args[0]); r == "esp" || r == "rsp" {
			s.sp += n
			return
		}

		switch v.kind {
		case "stackaddr":
			v.offset += n
			v.ref += "+" + strings.TrimSpace(args[1])
			s.write(args[0], v)

		case "const":
			v.n += n
			s.write(args[0], v)

		default:
			s.write(args[0], value{
				kind: "symbolic",
				expr: "(" + describe(v) + "+" +
					strings.TrimSpace(args[1]) + ")",
			})
		}

	case "and":
		if len(args) == 2 &&
			(reg(args[0]) == "esp" || reg(args[0]) == "rsp") {

			// Establish a new coordinate reference after
			// stack alignment. Earlier offsets are no longer
			// directly comparable.
			s.sp = 0
			s.bpOK = false
			s.mem = map[int64]value{}
			s.zeroes = map[int64]bool{}
			s.regs = map[string]value{}
			s.inputs = nil
		}

	case "xor":
		if len(args) == 2 && reg(args[0]) == reg(args[1]) {
			s.write(args[0], value{
				kind: "const",
				n:    0,
			})
		}

	case "call", "callq", "calll":
		s.onCall(in, format, out)

	case "cmp", "test":
		s.compare(in, args)

	default:
		if strings.HasPrefix(op, "j") && op != "jmp" {
			s.branch(in, out)
			return
		}

		if op == "leave" {
			if s.bpOK {
				s.sp = s.bp
			}
			s.bpOK = false

		} else if len(args) > 0 &&
			isReg(args[0]) &&
			op != "jmp" && op != "nop" {

			// Unknown register-writing operation:
			// discard the previous symbolic value.
			delete(s.regs, reg(args[0]))
		}
	}
}
