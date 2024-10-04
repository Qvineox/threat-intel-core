package targets

import (
	_ "embed"
	"encoding/json"
	"net"
)

//go:embed reserved_networks.json
var rnJSON string
var reservedNetworks ReservedNetworks

func init() {
	err := json.Unmarshal([]byte(rnJSON), &reservedNetworks)
	if err != nil {
		panic(err)
	}

	var cidr *net.IPNet

	for _, n := range reservedNetworks.Private {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}

	for _, n := range reservedNetworks.Private {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}

	for _, n := range reservedNetworks.Host {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}

	for _, n := range reservedNetworks.Documentation {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}

	for _, n := range reservedNetworks.Internet {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}

	for _, n := range reservedNetworks.Subnet {
		_, cidr, err = net.ParseCIDR(n)
		if err != nil {
			panic(err)
		}

		reservedNetworks.networks = append(reservedNetworks.networks, cidr)
	}
}

type ReservedNetworks struct {
	Private       []string `json:"private"`
	Host          []string `json:"host"`
	Documentation []string `json:"documentation"`
	Internet      []string `json:"internet"`
	Subnet        []string `json:"subnet"`

	networks []*net.IPNet
}

func CheckIsIPv4Reserved(ip net.IP) bool {
	for _, n := range reservedNetworks.networks {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}
