package netscan

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type scanData struct {
	ID       string
	Ipv4     string
	Port     string
	Service  string
	Hostname string
	Domain   string
	Type     string
	Private  string
}

var status, host, vuln, title, instance string

//CheckForVulns ...
func OutputScan(dd []string, scanid string, wg *sync.WaitGroup, flag string) {
	if flag == "csv" {
		line := `ip,port,proto,host,domain,type,private` + "\n"
		CSVOutput(line, scanid)
	}
	for _, v := range dd {
		details := strings.Fields(v)
		detailsComma := strings.Replace(v, " ", ",", -1)

		payload := scanData{
			ID:       scanid,
			Ipv4:     details[0],
			Port:     details[1],
			Service:  details[2],
			Hostname: details[3],
			Domain:   details[4],
			Type:     details[5],
			Private:  details[6],
		}
		b, err := json.Marshal(payload)
		if err != nil {
			fmt.Println("error:", err)
		}

		if flag == "elastic" {
			ElasticOut(b)
		}

		if flag == "csv" {
			CSVOutput(detailsComma, scanid)
		}

		if flag == "nmap" {
			NMAPOutput(details[0], scanid)
		}

	}
	wg.Done()
}
