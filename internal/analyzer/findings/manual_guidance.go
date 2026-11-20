package findings

import (
	"fmt"
	"strings"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/decoder"
)

// ManualGuidance describes a hypothesis and a manual validation
// procedure. It never represents a verified runtime exploit.
type ManualGuidance struct {
	Status               string
	Hypothesis           string
	Steps                []string
	Expected             string
	Limitations          string
	CandidateDistance    int64
	HasCandidateDistance bool
}

// AddManualGuidance enriches existing findings without modifying
// severity, confidence, or the original detection evidence.
func AddManualGuidance(
	items []Finding,
	flow dataflow.Result,
	graphs []cfg.Graph,
) []Finding {
	out := append([]Finding(nil), items...)

	byID := make(
		map[string]dataflow.CallTrace,
		len(flow.Calls),
	)

	for _, call := range flow.Calls {
		name := strings.Split(call.Target, "@")[0]

		if name != "gets" {
			continue
		}

		id := fmt.Sprintf(
			"API-gets-%d-%x",
			call.Section,
			call.Address,
		)

		byID[id] = call
	}

	for i := range out {
		call, found := byID[out[i].ID]
		if !found {
			continue
		}

		guide := &ManualGuidance{
			Status: "Hypothesis — requires manual verification",

			Hypothesis: "The unbounded gets() call may " +
				"overwrite storage adjacent to its destination.",

			Steps: []string{
				fmt.Sprintf(
					"Open the binary in an isolated local debugger "+
						"and stop at gets() call %#x.",
					call.Address,
				),

				"Inspect the first argument and record the " +
					"destination address.",

				"Supply controlled input and inspect nearby " +
					"memory before and after the call.",

				"Investigate subsequent conditional branches " +
					"and record any changes in execution.",
			},

			Expected: "An overwrite must be confirmed through " +
				"observed memory changes or execution behavior.",

			Limitations: "The API name alone does not prove " +
				"an overflow, destination capacity, or exploitability.",
		}

		if len(call.Arguments) > 0 {
			arg := call.Arguments[0].Value

			if arg.Kind == "stack-address" {
				guide.Steps[1] += " Modeled address: " +
					arg.String() + "."
			}
		}

		if relation, ok := detectI386AdjacentCheck(
			call,
			graphs,
		); ok {
			guide.HasCandidateDistance = true
			guide.CandidateDistance = relation.distance

			guide.Hypothesis = fmt.Sprintf(
				"A zero-initialized stack location is tested "+
					"after gets(). It lies %d bytes above "+
					"the modeled input destination.",
				relation.distance,
			)

			guide.Steps = append(
				guide.Steps,

				fmt.Sprintf(
					"Candidate local test: "+
						"python3 -c 'print(\"A\"*%d+\"B\")' | ./bin",
					relation.distance,
				),

				fmt.Sprintf(
					"Inspect %s after gets() and verify "+
						"whether the conditional branch at %#x "+
						"changes direction.",
					relation.checked,
					relation.branch,
				),
			)

			guide.Expected = "The controlled marker may " +
				"change the checked stack location and " +
				"affect the conditional branch."

			guide.Limitations = "The reported distance is a " +
				"candidate overwrite offset, not a proven " +
				"buffer size or a verified exploit."
		}

		out[i].ManualGuidance = guide
	}

	return out
}

type adjacentCheck struct {
	distance int64
	checked  string
	branch   uint64
}

// detectI386AdjacentCheck recognizes the narrow pattern:
//
// MOV  [ESP+target], 0
// LEA  reg, [ESP+source]
// MOV  [ESP], reg
// CALL gets
//
// Followed by a CFG fallthrough containing:
//
// MOV  reg, [ESP+target]
// TEST reg, reg
// Jcc  ...
//
// This avoids inventing offsets when the required evidence
// is not available.
func detectI386AdjacentCheck(
	call dataflow.CallTrace,
	graphs []cfg.Graph,
) (adjacentCheck, bool) {
	if len(call.Arguments) == 0 {
		return adjacentCheck{}, false
	}

	arg := call.Arguments[0].Value

	if arg.Kind != "stack-address" ||
		arg.Origin != "aligned-SP" {
		return adjacentCheck{}, false
	}

	for _, graph := range graphs {
		if graph.Section != call.Section {
			continue
		}

		for blockIndex, block := range graph.Blocks {
			insts := block.Instructions
			n := len(insts)

			if n < 4 {
				continue
			}

			last := insts[n-1]

			if last.Address != call.Address ||
				!guidanceMnemonic(last, "CALL") {
				continue
			}

			init := insts[n-4]
			lea := insts[n-3]
			pass := insts[n-2]

			if !guidanceMnemonic(init, "MOV") ||
				!guidanceMnemonic(lea, "LEA") ||
				!guidanceMnemonic(pass, "MOV") {
				continue
			}

			if len(init.Operands) != 2 ||
				len(lea.Operands) != 2 ||
				len(pass.Operands) != 2 {
				continue
			}

			target, okTarget := guidanceESPDisplacement(
				init.Operands[0],
			)

			source, okSource := guidanceESPDisplacement(
				lea.Operands[1],
			)

			passOffset, okPass := guidanceESPDisplacement(
				pass.Operands[0],
			)

			if !okTarget || !okSource || !okPass ||
				passOffset != 0 {
				continue
			}

			if init.Operands[0].Memory.SizeBytes != 4 ||
				pass.Operands[0].Memory.SizeBytes != 4 {
				continue
			}

			if init.Operands[1].Kind != decoder.OperandImmediate ||
				init.Operands[1].Immediate != 0 {
				continue
			}

			if lea.Operands[0].Kind != decoder.OperandRegister ||
				pass.Operands[1].Kind != decoder.OperandRegister {
				continue
			}

			if !strings.EqualFold(
				lea.Operands[0].Register,
				pass.Operands[1].Register,
			) {
				continue
			}

			distance := target - source

			if distance <= 0 || distance > 4096 {
				continue
			}

			// The call argument must agree with the
			// instruction-derived destination displacement.
			// This also establishes the modeled ESP origin.
			baseOffset := arg.StackOffset - source

			// Search the actual CFG fallthrough, not merely
			// the next block in the slice.
			for nextIndex, next := range graph.Blocks {
				if next.Start != block.End ||
					len(next.Instructions) < 3 {
					continue
				}

				if !guidanceFallthrough(
					graph.Edges,
					blockIndex,
					nextIndex,
				) {
					continue
				}

				load := next.Instructions[0]
				test := next.Instructions[1]
				branch := next.Instructions[2]

				if !guidanceMnemonic(load, "MOV") ||
					!guidanceMnemonic(test, "TEST") {
					continue
				}

				branchName := strings.ToUpper(
					branch.Mnemonic,
				)

				if !strings.HasPrefix(branchName, "J") ||
					branchName == "JMP" {
					continue
				}

				if len(load.Operands) != 2 ||
					len(test.Operands) != 2 {
					continue
				}

				if load.Operands[0].Kind !=
					decoder.OperandRegister ||
					test.Operands[0].Kind !=
						decoder.OperandRegister ||
					test.Operands[1].Kind !=
						decoder.OperandRegister {
					continue
				}

				checkedOffset, ok := guidanceESPDisplacement(
					load.Operands[1],
				)

				if !ok ||
					checkedOffset != target ||
					load.Operands[1].Memory.SizeBytes != 4 {
					continue
				}

				reg := load.Operands[0].Register

				if !strings.EqualFold(
					reg,
					test.Operands[0].Register,
				) || !strings.EqualFold(
					reg,
					test.Operands[1].Register,
				) {
					continue
				}

				checkedPosition := baseOffset + target

				return adjacentCheck{
					distance: distance,

					checked: fmt.Sprintf(
						"aligned-SP%+d",
						checkedPosition,
					),

					branch: branch.Address,
				}, true
			}
		}
	}

	return adjacentCheck{}, false
}

func guidanceMnemonic(
	inst decoder.Instruction,
	expected string,
) bool {
	return strings.EqualFold(
		inst.Mnemonic,
		expected,
	)
}

func guidanceESPDisplacement(
	op decoder.Operand,
) (int64, bool) {
	if op.Kind != decoder.OperandMemory {
		return 0, false
	}

	if !strings.EqualFold(op.Memory.Base, "ESP") ||
		op.Memory.Index != "" {
		return 0, false
	}

	return op.Memory.Displacement, true
}

func guidanceFallthrough(
	edges []cfg.Edge,
	from int,
	to int,
) bool {
	for _, edge := range edges {
		if edge.From == from &&
			edge.To == to &&
			edge.Kind == cfg.EdgeFallthrough {
			return true
		}
	}

	return false
}
