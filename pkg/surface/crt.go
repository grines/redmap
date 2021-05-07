package surface

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/grines/redmap/pkg/iptools"
)

var (
	crt []crtObject
)

type crtObject struct {
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	ID             int64  `json:"id"`
	NameValue      string `json:"name_value"`
	IssuerCaID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NotAfter       string `json:"not_after"`
}

//GetCRTs comment
func GetCRTs(domain string) Hosts {
	HostData := []Host{}
	h := Hosts{Host: HostData}

	hostlist := strings.Split(domain, ",")
	for _, v := range hostlist {
		data := GetCrt(v)
		for _, v := range data.Host {
			h.AddItem(v)
		}
	}
	return h
}

//GetCrt ok
func GetCrt(domain string) Hosts {
	url := "https://crt.sh/?q=" + domain + "&output=json"
	res, err := http.Get(url)
	if err != nil {
		panic(err.Error())
	}

	if res.StatusCode != 200 {
		HostData := []Host{}
		h := Hosts{Host: HostData}
		return h
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err.Error())
	}

	err2 := json.Unmarshal(body, &crt)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	HostData := []Host{}
	h := Hosts{Host: HostData}
	for k := range crt {
		result := strings.Split(crt[k].NameValue, "\n")
		for i := range result {
			if !strings.Contains(result[i], "*") {
				x := iptools.GrabIP(result[i])
				for _, ip := range x {
					if iptools.IsIPv4(ip.String()) {
						ips := ip.String()
						HostData := Host{
							Hostname: result[i],
							Domain:   domain,
							Private:  iptools.PrivateIP(ips),
							Ipv4:     ips,
							Type:     "CRT",
						}

						h.AddItem(HostData)
					}
				}
			}
		}
	}

	return h
}
