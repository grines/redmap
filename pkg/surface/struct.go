package surface

type Hosts struct {
	Host []Host
}

type Host struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Private  bool   `json:"private"`
	Ipv4     string `json:"ipv4"`
	Scanid   string `json:"scanid"`
}
