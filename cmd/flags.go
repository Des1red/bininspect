package cmd

import (
	"bininspect/internal/models"
	"fmt"
	"os"

	"github.com/Des1red/clihelp"
	"github.com/spf13/pflag"
)

func flags() (string, bool) {
	var help bool

	pflag.StringVarP(&models.Scope.Target, "target", "t", "", "target binary to analyze")
	pflag.BoolVarP(&help, "help", "h", false, "show help menu")

	pflag.Usage = printHelp
	pflag.Parse()

	if help {
		printHelp()
		return "", false
	}

	args := pflag.Args()

	if len(args) > 0 {
		switch args[0] {
		case "install", "uninstall":
			if len(args) == 1 && models.Scope.Target == "" {
				return args[0], true
			}
		}

		fmt.Fprintf(os.Stderr, "invalid command or arguments: %v\n\n", args)
		printHelp()
		return "", false
	}

	if models.Scope.Target == "" {
		printHelp()
		return "", false
	}

	return "inspect", true
}

func printHelp() {
	fmt.Println("BinInspect - Static Binary Analyzer")
	fmt.Println("\nUsage: bininspect [flags]")
	fmt.Println()
	fmt.Println("\nFlags:")
	clihelp.Print(
		clihelp.F("-t, --target", "path", "target binary to analyze"),
		clihelp.F("-h, --help", "", "show help menu"),
	)
	fmt.Println()
	fmt.Println("\nCommands:")
	clihelp.Print(
		clihelp.F("install", "", "build and install BinInspect"),
		clihelp.F("uninstall", "", "remove installed BinInspect binaries"),
	)
	fmt.Println()
	fmt.Println("\nExamples:")
	fmt.Println("  bininspect -t ./ex00/bin")
	fmt.Println("  bininspect install")
	fmt.Println("  bininspect uninstall")
}
