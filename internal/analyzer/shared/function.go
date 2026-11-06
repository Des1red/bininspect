package shared

import "regexp"

var functionHeader = regexp.MustCompile(
	`^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$`,
)

func FunctionHeader(line string) (string, string, bool) {
	match := functionHeader.FindStringSubmatch(line)
	if match == nil {
		return "", "", false
	}

	return match[1], match[2], true
}
