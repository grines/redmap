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
	shodan shodanObject
)

type shodanObject struct {
	Matches []struct {
		Hash      int    `json:"hash"`
		IP        int    `json:"ip"`
		Org       string `json:"org"`
		Isp       string `json:"isp"`
		Transport string `json:"transport"`
		Data      string `json:"data"`
		Asn       string `json:"asn"`
		Port      int    `json:"port"`
		Ssl       struct {
			Dhparams      interface{}   `json:"dhparams"`
			Tlsext        []interface{} `json:"tlsext"`
			Versions      []string      `json:"versions"`
			AcceptableCas []interface{} `json:"acceptable_cas"`
			Alpn          []interface{} `json:"alpn"`
			Cert          struct {
				SigAlg  string `json:"sig_alg"`
				Issued  string `json:"issued"`
				Expires string `json:"expires"`
				Pubkey  struct {
					Bits int    `json:"bits"`
					Type string `json:"type"`
				} `json:"pubkey"`
				Version    int `json:"version"`
				Extensions []struct {
					Data     string `json:"data"`
					Name     string `json:"name"`
					Critical bool   `json:"critical,omitempty"`
				} `json:"extensions"`
				Fingerprint struct {
					Sha256 string `json:"sha256"`
					Sha1   string `json:"sha1"`
				} `json:"fingerprint"`
				Issuer struct {
					C  string `json:"C"`
					CN string `json:"CN"`
					O  string `json:"O"`
				} `json:"issuer"`
				Expired bool `json:"expired"`
				Subject struct {
					C  string `json:"C"`
					ST string `json:"ST"`
					CN string `json:"CN"`
					O  string `json:"O"`
					L  string `json:"L"`
				} `json:"subject"`
			} `json:"cert"`
			Cipher struct {
				Version string `json:"version"`
				Bits    int    `json:"bits"`
				Name    string `json:"name"`
			} `json:"cipher"`
			Chain []string `json:"chain"`
			Ja3S  string   `json:"ja3s"`
			Ocsp  struct {
			} `json:"ocsp"`
		} `json:"ssl"`
		Hostnames []interface{} `json:"hostnames"`
		Location  struct {
			City         interface{} `json:"city"`
			RegionCode   interface{} `json:"region_code"`
			AreaCode     interface{} `json:"area_code"`
			Longitude    float64     `json:"longitude"`
			CountryCode3 interface{} `json:"country_code3"`
			Latitude     float64     `json:"latitude"`
			PostalCode   interface{} `json:"postal_code"`
			DmaCode      interface{} `json:"dma_code"`
			CountryCode  string      `json:"country_code"`
			CountryName  string      `json:"country_name"`
		} `json:"location"`
		Timestamp string        `json:"timestamp"`
		Domains   []interface{} `json:"domains"`
		HTTP      struct {
			RobotsHash  interface{}   `json:"robots_hash"`
			Redirects   []interface{} `json:"redirects"`
			Securitytxt interface{}   `json:"securitytxt"`
			Title       interface{}   `json:"title"`
			SitemapHash interface{}   `json:"sitemap_hash"`
			Robots      interface{}   `json:"robots"`
			Favicon     struct {
				Data     string `json:"data"`
				Hash     int    `json:"hash"`
				Location string `json:"location"`
			} `json:"favicon"`
			Host       string `json:"host"`
			HTML       string `json:"html"`
			Location   string `json:"location"`
			Components struct {
			} `json:"components"`
			SecuritytxtHash interface{} `json:"securitytxt_hash"`
			Server          string      `json:"server"`
			Sitemap         interface{} `json:"sitemap"`
			HTMLHash        int         `json:"html_hash"`
		} `json:"http"`
		Os     interface{} `json:"os"`
		Shodan struct {
			Crawler string `json:"crawler"`
			Ptr     bool   `json:"ptr"`
			ID      string `json:"id"`
			Module  string `json:"module"`
			Options struct {
				Hostname string `json:"hostname"`
				Scan     string `json:"scan"`
			} `json:"options"`
		} `json:"_shodan"`
		IPStr string `json:"ip_str"`
	} `json:"matches"`
	Total int `json:"total"`
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

	url := "https://api.shodan.io/shodan/host/search?key=" + api + "&query=" + domain
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

	for _, k := range shodan.Matches {
		host := k.Shodan.Options.Hostname
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
