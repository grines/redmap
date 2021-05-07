package netscan

import (
	"os"
)

func CSVOutput(data string, scanid string) {
	fileName := "/tmp/scanData-" + scanid

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(data + "\n"); err != nil {
		panic(err)
	}
}
