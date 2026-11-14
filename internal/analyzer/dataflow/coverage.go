package dataflow

import (
	"fmt"
	"sort"

	"bininspect/internal/analyzer/cfg"
)

func missingCallSites(
	graphs []cfg.Graph,
	traces []CallTrace,
	names map[uint64]string,
) []CallReference {
	type site struct {
		section int
		address uint64
	}

	seen := make(map[site]bool)

	// The analyzed call sites are already covered.
	for _, call := range traces {
		seen[site{
			section: call.Section,
			address: call.Address,
		}] = true
	}

	var missing []CallReference

	for _, graph := range graphs {
		for _, call := range graph.Calls {
			key := site{
				section: graph.Section,
				address: call.Address,
			}

			if seen[key] {
				continue
			}

			seen[key] = true

			target := "unresolved"

			switch {
			case call.Symbol != "":
				target = call.Symbol

			case call.HasTarget && !call.Indirect:
				if name := names[call.Target]; name != "" {
					target = name
				} else {
					target = fmt.Sprintf("%#x", call.Target)
				}
			}

			missing = append(missing, CallReference{
				Section:  graph.Section,
				Address:  call.Address,
				Target:   target,
				Indirect: call.Indirect,
			})
		}
	}

	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Section != missing[j].Section {
			return missing[i].Section < missing[j].Section
		}

		return missing[i].Address < missing[j].Address
	})

	return missing
}
