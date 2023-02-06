package utils

import (
	"log"
	"os"
)

func LogToFile(logFile string) error {
	if len(logFile) != 0 {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		log.SetOutput(f)
	}
	return nil
}
