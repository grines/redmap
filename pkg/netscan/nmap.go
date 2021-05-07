package netscan

import (
	"os"
)

func NMAPOutput(data string, scanid string) {
	fileName := "/tmp/nmap-" + scanid

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(data + ","); err != nil {
		panic(err)
	}
}
