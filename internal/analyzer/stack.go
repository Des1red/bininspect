package analyzer

import (
	"regexp"
	"strconv"
	"strings"

	"bininspect/internal/models"
)

var stackExpr = regexp.MustCompile(
	`\[\s*((?:e|r)sp|(?:e|r)bp)(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*\]`,
)

type stackPointer struct {
	offset    int64
	reference string
}

type stackRead struct {
	offset    int64
	reference string
	address   string
}

type stackInput struct {
	offset        int64
	reference     string
	call, address string
}

type stackTracker struct {
	sp, bp    int64
	bpValid   bool
	word      int64
	registers map[string]stackPointer
	slots     map[int64]stackPointer
	reads     map[string]stackRead
	zeroes    map[int64]bool
	inputs    []stackInput
	pending   *stackRead
}

func newStackTracker(word int64) stackTracker {
	return stackTracker{
		word:      word,
		registers: make(map[string]stackPointer),
		slots:     make(map[int64]stackPointer),
		reads:     make(map[string]stackRead),
		zeroes:    make(map[int64]bool),
	}
}

func StackRelations(a models.AssemblyAnalysis) []models.StackRelation {
	arch := strings.ToLower(a.Architecture)

	isX86 := strings.Contains(arch, "80386") ||
		strings.Contains(arch, "i386") ||
		strings.Contains(arch, "cpu386") ||
		strings.Contains(arch, "x86-64") ||
		strings.Contains(arch, "amd64")

	if !isX86 {
		return nil
	}

	word := int64(4)

	if strings.Contains(arch, "x86-64") ||
		strings.Contains(arch, "amd64") {
		word = 8
	}

	var relations []models.StackRelation
	var active string

	state := newStackTracker(word)

	for _, inst := range a.Instructions {
		if inst.Function != active {
			active = inst.Function
			state = newStackTracker(word)
		}

		state.step(inst, &relations)
	}

	return relations
}

func (s *stackTracker) ref(value string) (stackPointer, bool) {
	m := stackExpr.FindStringSubmatch(value)
	if m == nil {
		return stackPointer{}, false
	}

	var base int64

	switch m[1] {
	case "esp", "rsp":
		base = s.sp

	case "ebp", "rbp":
		if !s.bpValid {
			return stackPointer{}, false
		}
		base = s.bp
	}

	if m[3] != "" {
		delta, err := strconv.ParseInt(m[3], 0, 64)
		if err != nil {
			return stackPointer{}, false
		}

		if m[2] == "-" {
			delta = -delta
		}

		base += delta
	}

	return stackPointer{
		offset:    base,
		reference: m[0],
	}, true
}

func immediate(value string) (int64, bool) {
	value = strings.TrimSpace(
		strings.TrimLeft(strings.TrimSpace(value), "#$"),
	)

	n, err := strconv.ParseInt(value, 0, 64)
	return n, err == nil
}

func operands(value string) (string, string) {
	parts := strings.SplitN(value, ",", 2)

	if len(parts) < 2 {
		return "", ""
	}

	return strings.ToLower(strings.TrimSpace(parts[0])),
		strings.ToLower(strings.TrimSpace(parts[1]))
}

func (s *stackTracker) step(
	inst models.Instruction,
	out *[]models.StackRelation,
) {
	op := strings.ToLower(inst.Mnemonic)
	dst, src := operands(inst.Operands)

	switch op {
	case "push", "pushl", "pushq":
		s.sp -= s.word

		reg := strings.ToLower(strings.TrimSpace(inst.Operands))
		if p, ok := s.registers[reg]; ok {
			s.slots[s.sp] = p
		}

	case "pop", "popl", "popq":
		delete(s.slots, s.sp)
		s.sp += s.word
		delete(s.registers, strings.ToLower(strings.TrimSpace(inst.Operands)))

	case "and":
		if dst == "esp" || dst == "rsp" {
			// Stack alignment creates a new tracking reference.
			s.sp = 0
			s.bpValid = false
			s.registers = make(map[string]stackPointer)
			s.slots = make(map[int64]stackPointer)
			s.reads = make(map[string]stackRead)
			s.zeroes = make(map[int64]bool)
			s.inputs = nil
		}

	case "sub", "add":
		if n, ok := immediate(src); ok {
			if op == "sub" {
				n = -n
			}

			if dst == "esp" || dst == "rsp" {
				s.sp += n
			} else if p, exists := s.registers[dst]; exists {
				p.offset += n
				s.registers[dst] = p
			}
		} else if dst != "esp" && dst != "rsp" {
			delete(s.registers, dst)
		}

		delete(s.reads, dst)

	case "lea":
		if p, ok := s.ref(src); ok {
			s.registers[dst] = p
		} else {
			delete(s.registers, dst)
		}
		delete(s.reads, dst)

	case "mov":
		s.move(dst, src, inst.Address)

	case "xor":
		if dst == src {
			delete(s.registers, dst)
			delete(s.reads, dst)
		}

	case "call", "callq", "calll":
		s.call(inst)

	case "cmp", "test":
		s.pending = nil

		if r, ok := s.reads[dst]; ok &&
			((op == "test" && dst == src) ||
				(op == "cmp" && isZero(src))) {
			s.pending = &r
		} else if p, ok := s.ref(dst); ok &&
			op == "cmp" && isZero(src) {

			r := stackRead{
				offset:    p.offset,
				reference: p.reference,
				address:   inst.Address,
			}
			s.pending = &r
		}
	}

	if inst.Kind == "branch" {
		conditional := strings.HasPrefix(op, "j") &&
			op != "jmp" && op != "jmpq"

		if conditional && s.pending != nil {
			s.relate(*s.pending, inst, out)
		}

		s.pending = nil
	} else if op != "test" && op != "cmp" {
		s.pending = nil
	}
}

func isZero(value string) bool {
	n, ok := immediate(value)
	return ok && n == 0
}

func (s *stackTracker) move(dst, src, address string) {
	if (dst == "ebp" && src == "esp") ||
		(dst == "rbp" && src == "rsp") {
		s.bp = s.sp
		s.bpValid = true
	}

	if (dst == "esp" && src == "ebp") ||
		(dst == "rsp" && src == "rbp") {
		if s.bpValid {
			s.sp = s.bp
		}
	}

	if p, ok := s.ref(dst); ok {
		if v, exists := s.registers[src]; exists {
			s.slots[p.offset] = v
		} else {
			delete(s.slots, p.offset)
		}

		if isZero(src) {
			s.zeroes[p.offset] = true
		} else {
			delete(s.zeroes, p.offset)
		}
		return
	}

	if p, ok := s.ref(src); ok {
		delete(s.registers, dst)

		s.reads[dst] = stackRead{
			offset:    p.offset,
			reference: p.reference,
			address:   address,
		}
		return
	}

	if v, ok := s.registers[src]; ok {
		s.registers[dst] = v
	} else {
		delete(s.registers, dst)
	}

	if v, ok := s.reads[src]; ok {
		s.reads[dst] = v
	} else {
		delete(s.reads, dst)
	}
}

func (s *stackTracker) call(inst models.Instruction) {
	name := strings.Split(
		strings.Split(inst.Target, "@")[0], "+",
	)[0]
	name = strings.TrimLeft(name, "_")

	switch name {
	case "gets", "strcpy", "strcat", "sprintf", "vsprintf":
		var pointer stackPointer
		var ok bool

		if s.word == 4 {
			pointer, ok = s.slots[s.sp]
		} else if strings.EqualFold(models.Scope.Format, "PE") {
			pointer, ok = s.registers["rcx"]
		} else {
			pointer, ok = s.registers["rdi"]
		}

		if ok {
			s.inputs = append(s.inputs, stackInput{
				offset:    pointer.offset,
				reference: pointer.reference,
				call:      name,
				address:   inst.Address,
			})
		}
	}

	// Invalidate common caller-clobbered registers.
	for _, reg := range []string{
		"eax", "ecx", "edx",
		"rax", "rcx", "rdx",
		"rsi", "rdi",
		"r8", "r9", "r10", "r11",
	} {
		delete(s.registers, reg)
		delete(s.reads, reg)
	}
}

func (s *stackTracker) relate(
	read stackRead,
	branch models.Instruction,
	out *[]models.StackRelation,
) {
	for i := len(s.inputs) - 1; i >= 0; i-- {
		input := s.inputs[i]
		distance := read.offset - input.offset

		if distance <= 0 || distance > 8192 {
			continue
		}

		*out = append(*out, models.StackRelation{
			Function:         branch.Function,
			API:              input.call,
			CallSite:         input.address,
			InputReference:   input.reference,
			ReadSite:         read.address,
			CheckedReference: read.reference,
			BranchSite:       branch.Address,
			Distance:         distance,
			InitializedZero:  s.zeroes[read.offset],
		})
		return
	}
}
