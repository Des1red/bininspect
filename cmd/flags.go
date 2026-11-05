package cmd

import (
	"bininspect/internal/models"
	"fmt"
	"os"

	"github.com/Des1red/clihelp"
	"github.com/spf13/pflag"
)

func flags() {
	var help bool

	pflag.StringVarP(&models.Scope.Target, "target", "t", "", "target binary to analyze")
	pflag.BoolVarP(&help, "help", "h", false, "show help menu")

	pflag.Usage = printHelp
	pflag.Parse()

	if help {
		printHelp()
		return
	}

	if len(pflag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", pflag.Arg(0))
		printHelp()
		os.Exit(1)
	}

	if models.Scope.Target == "" {
		printHelp()
		return
	}
}

func printHelp() {
	fmt.Println("BinInspect - Static Binary Analyzer")
	fmt.Println("\nUsage: bininspect [flags]")

	fmt.Println("\nFlags:")
	clihelp.Print(
		clihelp.F("-t, --target", "path", "target binary to analyze"),
		clihelp.F("-h, --help", "", "show help menu"),
	)

	fmt.Println("\nExamples:")
	fmt.Println("  bininspect -t ./ex00/bin")
	fmt.Println("  bininspect --target /usr/bin/ls")
}
