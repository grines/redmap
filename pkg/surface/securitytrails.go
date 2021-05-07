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
	trails trailsObject
)

type trailsObject struct {
	Subdomains []string `json:"subdomains"`
	Meta       struct {
		LimitReached bool `json:"limit_reached"`
	} `json:"meta"`
	Endpoint string `json:"endpoint"`
}

//GetCRTs comment
func GetTrails(domain string) Hosts {
	HostData := []Host{}
	h := Hosts{Host: HostData}

	hostlist := strings.Split(domain, ",")
	for _, v := range hostlist {
		data := GetTrail(v)
		for _, v := range data.Host {
			h.AddItem(v)
		}
	}
	return h
}

//GetCrt ok
func GetTrail(domain string) Hosts {
	api := config.Configuration.Apitrails

	url := "https://api.securitytrails.com/v1/domain/" + domain + "/subdomains"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("apikey", api)
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

	err2 := json.Unmarshal(body, &trails)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	HostData := []Host{}
	h := Hosts{Host: HostData}
	for _, trail := range trails.Subdomains {
		host := trail + "." + domain
		x := iptools.GrabIP(host)
		for _, ip := range x {
			if iptools.IsIPv4(ip.String()) {
				ips := ip.String()
				HostData := Host{
					Hostname: host,
					Domain:   domain,
					Private:  iptools.PrivateIP(ips),
					Ipv4:     ips,
					Type:     "SecurityTrails",
				}

				h.AddItem(HostData)
			}
		}

	}

	return h
}
