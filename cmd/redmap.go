package redmap

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/drk1wi/Modlishka/log"
	"github.com/grines/redmap/config"
	"github.com/grines/redmap/pkg/netscan"
	"github.com/grines/redmap/pkg/surface"
)

var (
	domainPtr string
	outputPtr string
	configPtr string
	scanPtr   bool
)

//Start redmap
func Start() {

	//flags
	scanPtr := flag.Bool("scan", false, "Portscan hosts (Common Ports)")
	flag.StringVar(&domainPtr, "domain", "", "domain to map")
	flag.StringVar(&outputPtr, "output", "csv", "elastic/csv")
	flag.StringVar(&configPtr, "config", "config/config.json", "path to config.json")
	flag.Parse()

	config.Load(configPtr)

	//Combine hosts
	var combined surface.Hosts

	fmt.Println(`
	__________           .___ _____                 
	\______   \ ____   __| _//     \ _____  ______  
	 |       _// __ \ / __ |/  \ /  \\__  \ \____ \ 
	 |    |   \  ___// /_/ /    Y    \/ __ \|  |_> >
	 |____|_  /\___  >____ \____|__  (____  /   __/ 
		\/     \/     \/       \/     \/|__|   by grines`)
	fmt.Println("\t\tExternal Attack Surface Mapping\n")

	if domainPtr == "" {
		fmt.Println("\nFlag: -domain example.com  *required\n")
		os.Exit(0)
	}

	//CRT.sh
	log.Infof("* Ingesting CRT.SH")
	crthosts := surface.GetCRTs(domainPtr)
	s_crt := strconv.Itoa(len(crthosts.Host))
	log.Infof("* Crt.sh: " + s_crt + " hosts. \n")
	for _, h := range crthosts.Host {
		combined.AddItem(h)
	}

	//Shodan
	log.Infof("* Ingesting Shodan")
	shodanhosts := surface.GetShodans(domainPtr)
	s_shodan := strconv.Itoa(len(shodanhosts.Host))
	log.Infof("* Shodan: " + s_shodan + " hosts. \n")
	for _, h := range shodanhosts.Host {
		combined.AddItem(h)
	}

	//Security Trails
	log.Infof("* Ingesting Security Trails")
	trailshosts := surface.GetTrails(domainPtr)
	s_trails := strconv.Itoa(len(trailshosts.Host))
	log.Infof("* Security Trails: " + s_trails + " hosts. \n")
	for _, h := range trailshosts.Host {
		combined.AddItem(h)
	}

	//Virus Total
	log.Infof("* Ingesting Virus Total")
	vthosts := surface.GetVTs(domainPtr)
	s_vt := strconv.Itoa(len(vthosts.Host))
	log.Infof("* Virus Total: " + s_vt + " hosts.\n")
	for _, h := range vthosts.Host {
		combined.AddItem(h)
	}

	//Censys
	log.Infof("* Ingesting Censys")
	censyshosts := surface.GetCensyss(domainPtr)
	s_censys := strconv.Itoa(len(censyshosts.Host))
	log.Infof("* Censys: " + s_censys + " hosts. \n")
	for _, h := range censyshosts.Host {
		combined.AddItem(h)
	}

	//Remove duplicates based off of unique IP
	dedupCombined := surface.RemoveDuplicates(combined)

	//Save domains to file
	surface.SaveCSV(dedupCombined)

	//Performs basic port scan on hosts
	if *scanPtr == true {
		netscan.ScanProcess(dedupCombined, outputPtr)
	}

}
