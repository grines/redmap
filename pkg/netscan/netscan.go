package netscan

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/drk1wi/Modlishka/log"

	"github.com/grines/redmap/pkg/surface"
)

var (
	cidr     string
	scanType string
	port     int
	help     bool
)

type scanResult struct {
	Port    string
	State   string
	Service string
}

type ipAddress struct {
	IP net.IP
}

type IpData2 struct {
	Hostname         string `json:"hostname"`
	Domain           string `json:"domain"`
	Private          bool   `json:"private"`
	IPPublicIP       string `json:"ipaddr"`
	IPTagAccountName string `json:"accountid"`
	IPInstance       string `json:"instance"`
}

var portsList []int

func Scans(ips []surface.Host, scanid string) []string {

	//cidr := ip + "/32"
	scanType := "common"

	//Create channel for
	portsChannel := make(chan string, 5)

	startPort := 0
	endPort := 0
	protocol := "tcp"

	switch scanType {
	case "hashi":
		portsList = []int{8500, 4646, 5432}
	case "common":
		portsList = []int{21, 22, 23, 25, 53, 69, 79, 80, 88, 123, 389, 443, 445, 465, 636, 1080, 1194, 1433, 1812, 2483, 3389, 8080, 8443, 3306, 5432, 27017}
	case "quick":
		startPort = 0
		endPort = 10000
	case "single":
		startPort = port
		endPort = port
	case "all":
		startPort = 0
		endPort = 65535
	}

	//start the port scanner
	start(ips, startPort, endPort, protocol, portsChannel, scanType, portsList)

	var d []string
	//range over channel for events
	for elem := range portsChannel {
		d = append(d, elem)
	}
	//dd := removeDuplicateValues(d)

	return d
}

func start(ips []surface.Host, startPort int, endPort int, protocol string, portsChannel chan<- string, scanType string, portsList []int) {
	var wg sync.WaitGroup

	for _, v := range ips {
		if v.Ipv4 != "" {
			ip := hosts(v.Ipv4 + "/32")
			for _, v2 := range ip {
				// add scanPorts to waitgroup
				wg.Add(1)
				go scanPorts(startPort, endPort, protocol, v2.IP, &wg, portsChannel, scanType, portsList, v.Hostname, v.Domain, v.Scanid, v.Type, v.Private)
			}

		}
	}
	// defer channel close until waitgroup hits 0
	go func() {
		defer close(portsChannel)
		wg.Wait()
	}()
}

func scanPort(protocol string, hostname net.IP, port int) scanResult {
	result := scanResult{Port: strconv.Itoa(port), Service: protocol}
	address := hostname.String() + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, 2000*time.Millisecond)

	if err != nil {
		result.State = "Closed"
		return result
	}

	defer conn.Close()

	result.State = "Open"

	conn.Close()
	return result
}

func scanPorts(startPort int, endPort int, protocol string, ipv4 net.IP, wg *sync.WaitGroup, portsChannel chan<- string, scanType string, portsList []int, host string, domain string, scanid string, Type string, private bool) {
	if scanType == "hashi" || scanType == "common" {
		for _, v := range portsList {
			result := scanPort(protocol, ipv4, v)

			if result.State == "Open" {
				status := ipv4.String() + " " + result.Port + " " + result.Service + " " + host + " " + domain + "" + scanid + " " + Type + " " + strconv.FormatBool(private)
				log.Infof(status)
				portsChannel <- status
			}

		}
	}

	if scanType == "quick" || scanType == "single" || scanType == "all" {
		for i := startPort; i <= endPort; i++ {
			result := scanPort(protocol, ipv4, i)

			if result.State == "Open" {
				status := ipv4.String() + " " + result.Port + " " + result.Service + " " + host + " " + domain + " " + scanid + " " + Type + " " + strconv.FormatBool(private)
				portsChannel <- status
			}

		}
	}
	//call waitgroup done after port scans
	wg.Done()
}

//convert cidr to hosts slice
func hosts(cidr string) []ipAddress {
	var results []ipAddress

	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ipp := ipAddress{IP: ip}
		results = append(results, ipp)
	}
	return results
}

func removeDuplicateValues(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
