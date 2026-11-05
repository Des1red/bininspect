package bootstrap

import (
	"fmt"

	install "github.com/Des1red/goinstall/cmd"
)

func Uninstall() error {
	if err := install.SetBinaryName("bininspect"); err != nil {
		return err
	}

	if err := install.Uninstall(true, true); err != nil {
		return fmt.Errorf("uninstall bininspect: %w", err)
	}

	return nil
}
