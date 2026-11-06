package flow

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type value struct {
	kind      string
	offset, n int64
	expr, ref string

	fromStack bool
	refOffset int64
	readSite  string
}

type memref struct {
	stack      bool
	offset     int64
	expression string
}

var memPattern = regexp.MustCompile(`\[([^\]]+)\]`)

var regName = regexp.MustCompile(
	`^(?:[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:[89]|1[0-5])d?|[re]ip)$`,
)

func splitArgs(s string) []string {
	var parts []string
	start, depth := 0, 0

	for i, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(
					parts,
					strings.TrimSpace(s[start:i]),
				)
				start = i + 1
			}
		}
	}

	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

func reg(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "%")
}

func isReg(s string) bool {
	return regName.MatchString(reg(s))
}

func number(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	s = strings.TrimPrefix(s, "$")

	if s == "" {
		return 0, false
	}

	v, err := strconv.ParseInt(s, 0, 64)
	return v, err == nil
}

func (s *state) address(operand string) (memref, bool) {
	match := memPattern.FindStringSubmatch(
		strings.ToLower(operand),
	)
	if len(match) == 0 {
		return memref{}, false
	}

	inner := strings.ReplaceAll(
		strings.TrimSpace(match[1]), " ", "",
	)

	base := inner
	var delta int64

	for i := 1; i < len(inner); i++ {
		if inner[i] == '+' || inner[i] == '-' {
			base = inner[:i]

			v, ok := number(inner[i:])
			if !ok {
				return memref{
					expression: match[0],
				}, true
			}

			delta = v
			break
		}
	}

	switch base {
	case "esp", "rsp":
		return memref{
			stack:      true,
			offset:     s.sp + delta,
			expression: match[0],
		}, true

	case "ebp", "rbp":
		if s.bpOK {
			return memref{
				stack:      true,
				offset:     s.bp + delta,
				expression: match[0],
			}, true
		}

	default:
		if p, ok := s.regs[base]; ok {
			if p.kind == "stackaddr" {
				return memref{
					stack:      true,
					offset:     p.offset + delta,
					expression: match[0],
				}, true
			}

			if delta == 0 {
				return memref{
					expression: "*(" + describe(p) + ")",
				}, true
			}

			return memref{
				expression: fmt.Sprintf(
					"*(%s%+d)", describe(p), delta,
				),
			}, true
		}
	}

	return memref{expression: match[0]}, true
}

func describe(v value) string {
	switch v.kind {
	case "stackaddr":
		return v.ref

	case "const":
		return fmt.Sprintf("0x%x", v.n)

	case "symbolic":
		return v.expr
	}

	return "unknown"
}

func (s *state) read(op string) value {
	if m, ok := s.address(op); ok {
		if m.stack {
			v, exists := s.mem[m.offset]

			if !exists {
				v = value{
					kind: "symbolic",
					expr: "*" + m.expression,
				}
			}

			v.fromStack = true
			v.refOffset = m.offset
			v.ref = m.expression
			v.readSite = s.pc
			return v
		}

		return value{
			kind: "symbolic",
			expr: m.expression,
		}
	}

	if n, ok := number(op); ok {
		return value{kind: "const", n: n}
	}

	r := reg(op)

	if r == "esp" || r == "rsp" {
		return value{
			kind:   "stackaddr",
			offset: s.sp,
			ref:    r,
		}
	}

	if (r == "ebp" || r == "rbp") && s.bpOK {
		return value{
			kind:   "stackaddr",
			offset: s.bp,
			ref:    r,
		}
	}

	if v, ok := s.regs[r]; ok {
		return v
	}

	if isReg(op) {
		return value{
			kind: "symbolic",
			expr: r,
		}
	}

	return value{
		kind: "symbolic",
		expr: strings.TrimSpace(op),
	}
}

func (s *state) write(dst string, v value) {
	if m, ok := s.address(dst); ok {
		if m.stack {
			s.mem[m.offset] = v

			if v.kind == "const" && v.n == 0 {
				s.zeroes[m.offset] = true
			} else {
				delete(s.zeroes, m.offset)
			}
		}
		return
	}

	r := reg(dst)
	s.regs[r] = v

	if r == "ebp" || r == "rbp" {
		if v.kind == "stackaddr" {
			s.bp = v.offset
			s.bpOK = true
		} else {
			s.bpOK = false
		}
	}

	if (r == "esp" || r == "rsp") &&
		v.kind == "stackaddr" {
		s.sp = v.offset
	}
}
