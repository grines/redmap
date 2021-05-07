package surface

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/grines/redmap/config"
	"github.com/grines/redmap/pkg/iptools"
)

var (
	vts vtsObject
)

type vtsObject struct {
	Subdomains []string `json:"subdomains"`
}

//GetCRTs comment
func GetVTs(domain string) Hosts {
	HostData := []Host{}
	h := Hosts{Host: HostData}

	hostlist := strings.Split(domain, ",")
	for _, v := range hostlist {
		data := GetVT(v)
		for _, v := range data.Host {
			h.AddItem(v)
		}
	}
	return h
}

//GetVT ok
func GetVT(domain string) Hosts {
	api := config.Configuration.Apivirustotal

	url := "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + domain + "&apikey=" + api
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	res, _ := client.Do(req)

	if res.StatusCode != 200 {
		HostData := []Host{}
		h := Hosts{Host: HostData}
		return h
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err.Error())
	}

	err2 := json.Unmarshal(body, &vts)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	HostData := []Host{}
	h := Hosts{Host: HostData}
	for _, vt := range vts.Subdomains {
		x := iptools.GrabIP(vt)
		for _, ip := range x {
			if iptools.IsIPv4(ip.String()) {
				ips := ip.String()
				HostData := Host{
					Hostname: vt,
					Domain:   domain,
					Private:  iptools.PrivateIP(ips),
					Ipv4:     ips,
					Type:     "VirusTotal",
				}

				h.AddItem(HostData)
			}
		}

	}

	return h
}
