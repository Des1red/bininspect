package binary

import (
	"fmt"
	"math"
	"sort"
)

func normalizeELFLoadRegions(
	regions []Region,
) ([]Region, error) {
	if len(regions) < 2 {
		return regions, nil
	}

	sorted := append([]Region(nil), regions...)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address < sorted[j].Address
	})

	overlaps := false

	for i, r := range sorted {
		if r.MemorySize == 0 ||
			r.FileSize > r.MemorySize ||
			r.Address > math.MaxUint64-r.MemorySize ||
			r.FileOffset > math.MaxUint64-r.FileSize {
			return nil, fmt.Errorf(
				"invalid PT_LOAD region %q", r.Name,
			)
		}

		if i > 0 &&
			sorted[i-1].Address+
				sorted[i-1].MemorySize > r.Address {
			overlaps = true
		}
	}

	if !overlaps {
		return sorted, nil
	}

	bounds := make([]uint64, 0, 3*len(sorted))

	for _, r := range sorted {
		bounds = append(
			bounds,
			r.Address,
			r.Address+r.MemorySize,
		)

		if r.FileSize > 0 && r.FileSize < r.MemorySize {
			bounds = append(
				bounds,
				r.Address+r.FileSize,
			)
		}
	}

	sort.Slice(bounds, func(i, j int) bool {
		return bounds[i] < bounds[j]
	})

	unique := bounds[:0]

	for _, point := range bounds {
		if len(unique) == 0 ||
			unique[len(unique)-1] != point {
			unique = append(unique, point)
		}
	}

	var result []Region

	for i := 0; i+1 < len(unique); i++ {
		start, end := unique[i], unique[i+1]

		var chosen Region
		var chosenBacked bool
		var chosenOffset uint64

		found := false

		for _, r := range sorted {
			if r.Address > start {
				break
			}

			if start >= r.Address+r.MemorySize {
				continue
			}

			delta := start - r.Address
			backed := delta < r.FileSize
			off := r.FileOffset

			if backed {
				off += delta
			} else {
				off += r.FileSize
			}

			if !found {
				chosen = r
				chosenBacked = backed
				chosenOffset = off
				found = true
				continue
			}

			if chosen.Permissions != r.Permissions ||
				chosenBacked != backed ||
				(backed && chosenOffset != off) {
				return nil, fmt.Errorf(
					"conflicting PT_LOAD mappings at 0x%x (%s and %s)",
					start,
					chosen.Name,
					r.Name,
				)
			}
		}

		if !found {
			continue
		}

		segment := Region{
			Name:        chosen.Name,
			Address:     start,
			MemorySize:  end - start,
			FileOffset:  chosenOffset,
			Permissions: chosen.Permissions,
		}

		if chosenBacked {
			segment.FileSize = segment.MemorySize
		}

		n := len(result)

		if n > 0 &&
			canMergeLoadRegions(result[n-1], segment) {
			result[n-1].MemorySize += segment.MemorySize
			result[n-1].FileSize += segment.FileSize
			continue
		}

		result = append(result, segment)
	}

	return result, nil
}

func canMergeLoadRegions(a, b Region) bool {
	if a.Address+a.MemorySize != b.Address ||
		a.Permissions != b.Permissions {
		return false
	}

	if a.FileSize < a.MemorySize {
		return b.FileSize == 0
	}

	return a.FileOffset+a.FileSize == b.FileOffset
}
