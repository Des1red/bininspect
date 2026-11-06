package flow

import (
	"strings"

	"bininspect/internal/models"
)

func (s *state) compare(
	in models.Instruction,
	args []string,
) {
	s.pending = nil

	if len(args) != 2 {
		return
	}

	left := s.read(args[0])
	right := s.read(args[1])

	var checked value
	var other value

	switch {
	case left.fromStack:
		checked = left
		other = right

	case right.fromStack:
		checked = right
		other = left

	default:
		return
	}

	if strings.EqualFold(in.Mnemonic, "test") {
		if reg(args[0]) != reg(args[1]) {
			return
		}

		other = value{
			kind: "const",
			n:    0,
		}
	}

	compared := describe(other)

	if other.kind != "const" {
		compared = "unknown"
	}

	readSite := checked.readSite
	if readSite == "" {
		readSite = in.Address
	}

	s.pending = &comparison{
		offset: checked.refOffset,
		ref:    checked.ref,
		read:   readSite,
		value:  compared,
	}
}

func (s *state) branch(
	in models.Instruction,
	out *Result,
) {
	checked := s.pending
	s.pending = nil

	if checked == nil {
		return
	}

	for i := len(s.inputs) - 1; i >= 0; i-- {
		input := s.inputs[i]
		distance := checked.offset - input.offset

		if distance <= 0 || distance > 1<<20 {
			continue
		}

		// A known upper bound that cannot reach the checked
		// location rules out this particular relationship.
		if input.maxBytes >= 0 &&
			input.maxBytes <= distance {
			continue
		}

		out.Relations = append(
			out.Relations,
			models.StackRelation{
				Function:         in.Function,
				API:              input.api,
				CallSite:         input.call,
				InputReference:   input.ref,
				SourceReference:  input.source,
				ReadSite:         checked.read,
				CheckedReference: checked.ref,
				BranchSite:       in.Address,
				Distance:         distance,
				InitializedZero:  s.zeroes[checked.offset],
				ComparedValue:    checked.value,
				BranchCondition:  in.Mnemonic,
				Confidence:       "heuristic",
			},
		)

		return
	}
}
