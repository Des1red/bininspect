package functions

import (
	"strconv"
	"strings"

	"bininspect/internal/analyzer/shared"
	"bininspect/internal/models"
)

func Analyze(
	assembly models.AssemblyAnalysis,
) ([]models.FunctionCall, []models.FunctionInfo) {

	var calls []models.FunctionCall
	var functions []models.FunctionInfo

	byName := make(map[string]int)
	byAddress := make(map[uint64]string)

	// Discover definitions from the disassembly.
	for _, line := range strings.Split(
		models.Knowledge.Assembly, "\n",
	) {
		address, name, ok := shared.FunctionHeader(line)
		if !ok {
			continue
		}

		if _, exists := byName[name]; exists {
			continue
		}

		byName[name] = len(functions)

		functions = append(functions, models.FunctionInfo{
			Name:    name,
			Address: address,
		})

		if value, ok := hexAddress(address); ok {
			byAddress[value] = name
		}
	}

	// Analyze parsed instructions.
	for _, inst := range assembly.Instructions {
		if index, exists := byName[inst.Function]; exists {
			functions[index].Instructions++
		}

		if inst.Kind != "call" {
			continue
		}

		call := models.FunctionCall{
			Address:     inst.Address,
			Caller:      inst.Function,
			Target:      inst.Target,
			Instruction: inst.Mnemonic + " " + inst.Operands,
			Indirect:    inst.Indirect,
		}

		if !inst.Indirect {
			call.Name = resolveFunctionName(
				inst.Target,
				byAddress,
			)
		}

		calls = append(calls, call)

		// Build caller -> callee relationships.
		if caller, exists := byName[call.Caller]; exists {
			callee := call.Name

			if callee == "" {
				callee = "<unresolved>"
			}

			functions[caller].Calls = append(
				functions[caller].Calls,
				callee,
			)
		}

		// Build reverse callee -> caller relationships.
		if callee, exists := byName[call.Name]; exists &&
			call.Caller != "" {

			functions[callee].Callers = append(
				functions[callee].Callers,
				call.Caller,
			)
		}
	}

	// Remove duplicate call relationships.
	for i := range functions {
		functions[i].Calls = shared.Unique(functions[i].Calls)
		functions[i].Callers = shared.Unique(functions[i].Callers)
	}

	return calls, functions
}

func resolveFunctionName(
	target string,
	addresses map[uint64]string,
) string {

	target = strings.TrimSpace(target)

	if target == "" {
		return ""
	}

	if address, ok := hexAddress(target); ok {
		if name, exists := addresses[address]; exists {
			return name
		}

		// Numeric address without a known symbol.
		return ""
	}

	// Symbolic target, potentially with an offset or suffix.
	name := strings.Split(target, "+")[0]
	name = strings.Split(name, "@")[0]

	return strings.TrimSpace(name)
}

func hexAddress(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")

	if value == "" {
		return 0, false
	}

	n, err := strconv.ParseUint(value, 16, 64)
	return n, err == nil
}
