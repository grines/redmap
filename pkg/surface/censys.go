package surface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/grines/redmap/config"
	"github.com/grines/redmap/pkg/iptools"
)

var (
	censys censysObject
)

type censysObject struct {
	Status  string `json:"status"`
	Results []struct {
		IP string `json:"ip"`
	} `json:"results"`
	Metadata struct {
		Count       int    `json:"count"`
		Query       string `json:"query"`
		BackendTime int    `json:"backend_time"`
		Page        int    `json:"page"`
		Pages       int    `json:"pages"`
	} `json:"metadata"`
}

//GetCRTs comment
func GetCensyss(domain string) Hosts {
	HostData := []Host{}
	h := Hosts{Host: HostData}

	hostlist := strings.Split(domain, ",")

	//Setting to 10 to limit api calls.
	count := 10
	for i := 1; i < count; i++ {
		for _, v := range hostlist {
			data := GetCensys(v, i)
			for _, v := range data.Host {
				h.AddItem(v)
			}
		}
	}
	return h
}

//GetCrt ok
func GetCensys(domain string, page int) Hosts {
	UID := config.Configuration.Apicensysuid
	SECRET := config.Configuration.Apicensyssecret
	p := strconv.Itoa(page)

	url := "https://censys.io/api/v1/search/ipv4"

	query := fmt.Sprintf(`{ "query": "443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: %s", "fields": ["ip"], "page": %s, "flatten": false }`, domain, p)
	var jsonStr = []byte(query)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Add("Authorization", "Basic "+basicAuth(UID, SECRET))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		HostData := []Host{}
		h := Hosts{Host: HostData}
		return h
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err.Error())
	}

	err2 := json.Unmarshal(body, &censys)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	HostData := []Host{}
	h := Hosts{Host: HostData}
	for _, k := range censys.Results {
		x := iptools.GrabIP(k.IP)
		for _, ip := range x {
			if iptools.IsIPv4(ip.String()) {
				ips := ip.String()
				HostData := Host{
					Hostname: k.IP,
					Domain:   domain,
					Private:  iptools.PrivateIP(ips),
					Ipv4:     ips,
					Type:     "Censys",
				}

				h.AddItem(HostData)
			}
		}
	}

	return h

}
