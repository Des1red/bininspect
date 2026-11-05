package collect

import (
	"fmt"
	"os/exec"

	"bininspect/internal/models"
)

func run(name string, args ...string) (string, error) {
	args = append(args, "--", models.Scope.Target)

	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, output)
	}

	return string(output), nil
}
