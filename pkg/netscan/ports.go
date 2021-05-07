package netscan

import (
	"fmt"
	"strconv"
)

var portList = map[int]string{
	22:   "ssh",
	8500: "consul",
	4646: "nomad",
	5432: "postgres",
	8200: "vault",
	80:   "http",
	8080: "http",
	443:  "https",
	8443: "https",
	21:   "ftp",
	3389: "rdp",
	445:  "smb",
	389:  "ldap",
	636:  "ldaps",
	25:   "smtp",
	1433: "sql",
}

func getPort(port string) string {
	i, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println(err)
	}
	for k, v := range portList {
		if k == i {
			return v
		}
	}
	return "unknown"
}
