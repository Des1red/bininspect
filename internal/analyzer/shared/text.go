package shared

import "strings"

func Lines(data string) []string {
	return strings.Split(data, "\n")
}

func Unique(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))

	for _, item := range items {
		item = strings.TrimSpace(item)

		if item == "" || seen[item] {
			continue
		}

		seen[item] = true
		result = append(result, item)
	}

	return result
}

func Matching(data string, terms ...string) []string {
	var result []string

	for _, line := range Lines(data) {
		for _, term := range terms {
			if strings.Contains(line, term) {
				result = append(result, line)
				break
			}
		}
	}

	return Unique(result)
}

func Field(data, prefix string) string {
	for _, line := range Lines(data) {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(
				strings.TrimPrefix(line, prefix),
			)
		}
	}

	return ""
}
