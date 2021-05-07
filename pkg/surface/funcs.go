package surface

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/drk1wi/Modlishka/log"
	"github.com/lithammer/shortuuid"
)

func (h *Hosts) AddItem(item Host) []Host {
	h.Host = append(h.Host, item)
	return h.Host
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func RemoveDuplicates(elements Hosts) []Host { // change string to int here if required
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{} // change string to int here if required
	result := []Host{}               // change string to int here if required

	for _, v := range elements.Host {
		if encountered[string(v.Ipv4)] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[string(v.Ipv4)] = true
			// Append to result slice.
			result = append(result, v)
		}
	}
	// Return the new slice.
	return result
}

func SaveCSV(data []Host) {
	scanid := shortuuid.New()
	fileName := "/tmp/DomainData-" + scanid

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	var domains []string
	line := `ip,host,domain,type` + "\n"
	f.WriteString(line + "\n")
	for _, d := range data {
		domain := fmt.Sprintf(d.Ipv4 + "," + d.Hostname + "," + d.Domain + "," + d.Type)
		if _, err = f.WriteString(domain + "\n"); err != nil {
			panic(err)
		}
		domains = append(domains, domain)
	}
	fmt.Println()
	log.Infof("* Domain Dump: " + fileName)
	fmt.Println()

}
