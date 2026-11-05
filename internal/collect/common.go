package collect

import "bininspect/internal/models"

func CommonEngine() error {
	var err error

	models.Knowledge.File, err = File()
	if err != nil {
		return err
	}

	models.Knowledge.Strings, err = Strings()
	return err
}

func File() (string, error) {
	return run("file")
}

func Strings() (string, error) {
	return run("strings", "-a")
}
