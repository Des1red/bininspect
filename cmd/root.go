package cmd

import (
	"fmt"
	"os"

	"bininspect/internal"
	"bininspect/internal/bootstrap"
)

func Root() {
	command, ok := flags()
	if !ok {
		return
	}

	var err error

	switch command {
	case "install":
		err = bootstrap.Install()

	case "uninstall":
		err = bootstrap.Uninstall()

	case "inspect":
		internal.Inspect()
		return
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
