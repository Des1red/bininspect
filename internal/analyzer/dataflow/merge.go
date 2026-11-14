package dataflow

// mergeCallSites retains one record per decoded call address.
//
// If overlapping function candidates produce different facts,
// only values that agree across all contexts are retained.
func mergeCallSites(calls []CallTrace) []CallTrace {
	type site struct {
		section int
		address uint64
	}

	indices := make(map[site]int, len(calls))
	result := make([]CallTrace, 0, len(calls))

	for _, current := range calls {
		key := site{
			section: current.Section,
			address: current.Address,
		}

		index, exists := indices[key]
		if !exists {
			copyOfCall := current
			copyOfCall.Arguments = append(
				[]Argument(nil),
				current.Arguments...,
			)

			indices[key] = len(result)
			result = append(result, copyOfCall)
			continue
		}

		existing := &result[index]

		differentOwner := existing.Function != current.Function

		if differentOwner {
			existing.Function = "ambiguous owner"
		}

		if existing.Target != current.Target {
			existing.Target = "unresolved"
		}

		existing.Indirect = existing.Indirect || current.Indirect

		for i := range existing.Arguments {
			if i >= len(current.Arguments) ||
				existing.Arguments[i].Position !=
					current.Arguments[i].Position ||
				existing.Arguments[i].Location !=
					current.Arguments[i].Location {

				existing.Arguments[i].Value = Value{}
				continue
			}

			left := existing.Arguments[i].Value
			right := current.Arguments[i].Value

			if left != right {
				existing.Arguments[i].Value = Value{}
				continue
			}

			// An entry-SP-relative pointer is relative to
			// a particular function's entry state. Equal
			// offsets from different functions do not
			// establish the same pointer.
			if differentOwner && left.Kind == "stack-address" {
				existing.Arguments[i].Value = Value{}
			}
		}
	}

	return result
}
