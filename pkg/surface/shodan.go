package surface

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/grines/redmap/config"
	"github.com/grines/redmap/pkg/iptools"
)

var (
	shodan shodanObject
)

type shodanObject struct {
	More   bool     `json:"more"`
	Domain string   `json:"domain"`
	Tags   []string `json:"tags"`
	Data   []struct {
		Tags      []string  `json:"tags,omitempty"`
		Subdomain string    `json:"subdomain"`
		Type      string    `json:"type"`
		Ports     []int     `json:"ports,omitempty"`
		Value     string    `json:"value"`
		LastSeen  time.Time `json:"last_seen"`
	} `json:"data"`
	Subdomains []string `json:"subdomains"`
}

//GetCRTs comment
func GetShodans(domain string) Hosts {
	HostData := []Host{}
	h := Hosts{Host: HostData}

	hostlist := strings.Split(domain, ",")
	for _, v := range hostlist {
		data := GetShodan(v)
		for _, v := range data.Host {
			h.AddItem(v)
		}
	}
	return h
}

//GetCrt ok
func GetShodan(domain string) Hosts {
	api := config.Configuration.Apishodan

	url := "https://api.shodan.io/dns/domain/" + domain + "?key=" + api
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

	err2 := json.Unmarshal(body, &shodan)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	HostData := []Host{}
	h := Hosts{Host: HostData}

	for _, k := range shodan.Subdomains {
		host := k + "." + domain
		x := iptools.GrabIP(host)
		for _, ip := range x {
			if iptools.IsIPv4(ip.String()) {
				ips := ip.String()
				HostData := Host{
					Hostname: host,
					Domain:   domain,
					Private:  iptools.PrivateIP(ips),
					Ipv4:     ips,
					Type:     "Shodan",
				}

				h.AddItem(HostData)
			}
		}

	}

	return h
}
