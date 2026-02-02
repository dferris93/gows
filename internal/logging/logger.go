package logging

import (
	"log"
	"os"
)

func NewLogger(path string) (*log.Logger, func() error, error) {
	if path == "" || path == "-" {
		return log.New(os.Stdout, "", 0), func() error { return nil }, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return nil, nil, err
	}

	return log.New(file, "", 0), file.Close, nil
}
