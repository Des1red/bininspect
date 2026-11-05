package bootstrap

import (
	"fmt"

	install "github.com/Des1red/goinstall/cmd"
)

func Install() error {
	if err := install.SetBinaryName("bininspect"); err != nil {
		return err
	}

	if err := install.Install(true, true); err != nil {
		return fmt.Errorf("install bininspect: %w", err)
	}

	return nil
}
