package analyzer

import (
	"regexp"
	"strconv"
	"strings"
)

var instructionPattern = regexp.MustCompile(
	`^\s*([0-9a-fA-F]+):\s`,
)

func lines(data string) []string {
	return strings.Split(data, "\n")
}

func unique(items []string) []string {
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

func matching(data string, terms ...string) []string {
	var result []string

	for _, line := range lines(data) {
		for _, term := range terms {
			if strings.Contains(line, term) {
				result = append(result, line)
				break
			}
		}
	}

	return unique(result)
}

func field(data, prefix string) string {
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(
				strings.TrimPrefix(line, prefix),
			)
		}
	}

	return ""
}

func number(value string) uint64 {
	n, _ := strconv.ParseUint(value, 0, 64)
	return n
}

func instruction(line string) (string, string, bool) {
	match := instructionPattern.FindStringSubmatch(line)
	if match == nil {
		return "", "", false
	}

	parts := strings.Split(line, "\t")
	if len(parts) < 3 {
		return "", "", false
	}

	return match[1], strings.TrimSpace(parts[len(parts)-1]), true
}
