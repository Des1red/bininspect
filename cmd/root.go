package cmd

import "bininspect/internal"

func Root() {
	flags()
	internal.Inspect()
}
