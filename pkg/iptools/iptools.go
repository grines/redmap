package iptools

import (
	"fmt"
	"net"
	"strings"
)

//IsIPv4 notes
func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

//IsIPv6 notes
func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

//PrivateIP notes
func PrivateIP(ip string) bool {
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		fmt.Print("Invalid IP")
	} else {
		_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
		_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
		_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
		private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	}
	return private
}

//GrabIP commments
func GrabIP(hostname string) []net.IP {
	addr, _ := net.LookupIP(hostname)
	return addr
}
