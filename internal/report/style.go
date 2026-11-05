package report

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	gray   = "\033[90m"

	width = 72
)

var colors bool

func initStyle() {
	info, err := os.Stdout.Stat()

	colors = err == nil &&
		info.Mode()&os.ModeCharDevice != 0 &&
		os.Getenv("NO_COLOR") == "" &&
		os.Getenv("TERM") != "dumb"
}

func paint(color, value string) string {
	if !colors {
		return value
	}

	return color + value + reset
}

func header(title string) {
	fmt.Println()
	fmt.Println(paint(bold+cyan, title))
	fmt.Println(paint(gray, strings.Repeat("━", width)))
}

func box(title string, rows ...string) {
	fmt.Println("┌" + strings.Repeat("─", width) + "┐")
	boxLine(paint(bold+cyan, title))
	fmt.Println("├" + strings.Repeat("─", width) + "┤")

	for _, row := range rows {
		for _, line := range wrap(row, width-2) {
			boxLine(line)
		}
	}

	fmt.Println("└" + strings.Repeat("─", width) + "┘")
}

func boxLine(value string) {
	visible := stripANSI(value)
	length := utf8.RuneCountInString(visible)

	padding := width - length - 2
	if padding < 0 {
		padding = 0
	}

	fmt.Printf("│ %s%s │\n", value, strings.Repeat(" ", padding))
}

func wrap(value string, limit int) []string {
	var result []string

	for _, paragraph := range strings.Split(value, "\n") {
		if paragraph == "" {
			result = append(result, "")
			continue
		}

		var line string

		for _, word := range strings.Fields(paragraph) {
			if line != "" &&
				utf8.RuneCountInString(line)+
					utf8.RuneCountInString(word)+1 > limit {

				result = append(result, line)
				line = ""
			}

			// Split individual words that exceed the limit.
			for utf8.RuneCountInString(word) > limit {
				runes := []rune(word)
				if line != "" {
					result = append(result, line)
					line = ""
				}
				result = append(result, string(runes[:limit]))
				word = string(runes[limit:])
			}

			if line != "" {
				line += " "
			}
			line += word
		}

		result = append(result, line)
	}

	return result
}

func stripANSI(value string) string {
	var result strings.Builder
	escape := false

	for _, r := range value {
		if r == '\033' {
			escape = true
			continue
		}

		if escape {
			if r == 'm' {
				escape = false
			}
			continue
		}

		result.WriteRune(r)
	}

	return result.String()
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "enabled", "full", "detected":
		return green

	case "disabled", "high", "critical":
		return red

	case "partial", "possible", "medium",
		"compatible", "indicated":
		return yellow

	default:
		return gray
	}
}

func short(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")

	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}

	if limit <= 3 {
		return string(runes[:limit])
	}

	return string(runes[:limit-3]) + "..."
}
