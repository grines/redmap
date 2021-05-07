package netscan

import (
	"fmt"
	"sync"

	"github.com/drk1wi/Modlishka/log"
	"github.com/grines/redmap/pkg/surface"
	"github.com/lithammer/shortuuid"
)

//ScanProcess ...
func ScanProcess(data []surface.Host, flag string) {
	var wg sync.WaitGroup

	scanid := shortuuid.New()

	log.Infof("Scanning: %v hosts\n", len(data))
	out := Scans(data, scanid)
	wg.Add(1)
	go OutputScan(out, scanid, &wg, flag)
	wg.Wait()

	fmt.Println()
	log.Infof("* ScanID: " + scanid)
	log.Infof("* Results: /tmp/scanData-" + scanid)
}
