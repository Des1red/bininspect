package flow

import (
	"fmt"
	"strings"

	"bininspect/internal/models"
)

type signature struct {
	args, dest, source, bound int
	boundExtra                int64
}

// Argument indexes are zero-based.
// -1 means that the argument does not apply.
var signatures = map[string]signature{
	"gets":     {1, 0, -1, -1, 0},
	"strcpy":   {2, 0, 1, -1, 0},
	"strcat":   {2, 0, 1, -1, 0},
	"sprintf":  {2, 0, 1, -1, 0},
	"vsprintf": {3, 0, 1, -1, 0},

	"memcpy":  {3, 0, 1, 2, 0},
	"memmove": {3, 0, 1, 2, 0},
	"strncpy": {3, 0, 1, 2, 0},
	"strncat": {3, 0, 1, 2, 1},

	"fgets":    {3, 0, -1, 1, 0},
	"snprintf": {3, 0, 2, 1, 0},
	"read":     {3, 1, -1, 2, 0},
	"recv":     {3, 1, -1, 2, 0},
}

func cleanName(s string) string {
	s = strings.Split(s, "+")[0]
	s = strings.Split(s, "@")[0]
	s = strings.TrimPrefix(s, "__imp_")
	return strings.TrimLeft(s, "_")
}

func (s *state) arg(
	index int,
	format string,
) (value, string) {
	if s.word == 4 {
		offset := s.sp + int64(index)*4
		location := fmt.Sprintf("[esp+0x%x]", index*4)

		if v, ok := s.mem[offset]; ok {
			return v, location
		}

		return value{}, location
	}

	registers := []string{
		"rdi", "rsi", "rdx", "rcx", "r8", "r9",
	}

	if strings.EqualFold(format, "PE") {
		registers = []string{
			"rcx", "rdx", "r8", "r9",
		}
	}

	if index >= len(registers) {
		return value{}, "unmodeled stack argument"
	}

	location := registers[index]

	if v, ok := s.regs[location]; ok {
		return v, location
	}

	return value{}, location
}

func (s *state) onCall(
	in models.Instruction,
	format string,
	out *Result,
) {
	name := cleanName(in.Target)
	sig, exists := signatures[name]

	if exists {
		call := models.CallFlow{
			Function: in.Function,
			API:      name,
			Address:  in.Address,
		}

		vals := make([]value, sig.args)

		for i := 0; i < sig.args; i++ {
			v, location := s.arg(i, format)
			vals[i] = v

			arg := models.ArgumentFlow{
				Position:   i + 1,
				Location:   location,
				Expression: describe(v),
			}

			if v.kind == "stackaddr" {
				arg.StackReference = v.ref
			}

			call.Arguments = append(call.Arguments, arg)
		}

		out.Calls = append(out.Calls, call)

		if sig.dest >= 0 && sig.dest < len(vals) {
			dst := vals[sig.dest]

			if dst.kind == "stackaddr" {
				maxBytes := int64(-1)

				if sig.bound >= 0 &&
					sig.bound < len(vals) &&
					vals[sig.bound].kind == "const" {

					maxBytes = vals[sig.bound].n +
						sig.boundExtra
				}

				source := "external input"

				if sig.source >= 0 &&
					sig.source < len(vals) {
					source = describe(vals[sig.source])
				}

				s.inputs = append(s.inputs, sink{
					api:      name,
					call:     in.Address,
					ref:      dst.ref,
					source:   source,
					offset:   dst.offset,
					maxBytes: maxBytes,
				})
			}
		}
	}

	// Invalidate caller-clobbered registers.
	clobbered := []string{
		"eax", "ecx", "edx",
	}

	if s.word == 8 {
		clobbered = []string{
			"rax", "rcx", "rdx",
			"rsi", "rdi", "r8",
			"r9", "r10", "r11",
		}

		if strings.EqualFold(format, "PE") {
			clobbered = []string{
				"rax", "rcx", "rdx",
				"r8", "r9", "r10", "r11",
			}
		}
	}

	for _, r := range clobbered {
		delete(s.regs, r)
	}
}
