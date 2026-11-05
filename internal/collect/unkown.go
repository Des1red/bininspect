package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"bininspect/internal/models"
)

type UnknownData struct {
	Info    string
	RawData string
}

func UnknownEngine() error {
	data, err := Unknown()
	if err != nil {
		return err
	}

	models.Knowledge.Unknown = data.Info
	models.Knowledge.RawData = data.RawData

	return nil
}

func Unknown() (UnknownData, error) {
	var data UnknownData

	f, err := os.Open(models.Scope.Target)
	if err != nil {
		return data, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return data, err
	}

	if !info.Mode().IsRegular() {
		return data, fmt.Errorf("target is not a regular file")
	}

	hasher := sha256.New()

	if _, err := io.Copy(hasher, f); err != nil {
		return data, err
	}

	data.Info = fmt.Sprintf(
		"Format: Unknown\nSize: %d bytes\nSHA256: %x\n",
		info.Size(),
		hasher.Sum(nil),
	)

	data.RawData, err = preview(models.Scope.Target)

	return data, err
}

func preview(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buffer := make([]byte, 256)

	n, err := f.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}

	return hex.Dump(buffer[:n]), nil
}
