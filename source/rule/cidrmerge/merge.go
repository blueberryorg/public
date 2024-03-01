package cidrmerge

import (
	"errors"
	"net"
)

type ipNets []*net.IPNet

func (nets ipNets) toCIDRs() []string {
	var cidrs []string
	for _, net := range nets {
		cidrs = append(cidrs, net.String())
	}

	return cidrs
}

// MergeIPNets accepts a list of IP networks and merges them into the smallest possible list of IPNets.
// It merges adjacent subnets where possible, those contained within others and removes any duplicates.
func MergeIPNets(nets []*net.IPNet) ([]*net.IPNet, error) {
	if nets == nil {
		return nil, nil
	}
	if len(nets) == 0 {
		return make([]*net.IPNet, 0), nil
	}

	// Split into IPv4 and IPv6 lists.
	// Merge the list separately and then combine.
	var block4s cidrBlock4s
	var block6s cidrBlock6s
	for _, net := range nets {
		if net.IP.To4() != nil {
			block4s = append(block4s, newBlock4(net.IP.To4(), net.Mask))
		} else if net.IP.To16() != nil {
			block6s = append(block6s, newBlock6(net.IP.To16(), net.Mask))
		} else {
			return nil, errors.New("Not implemented")
		}
	}

	var result []*net.IPNet
	{
		merged, err := merge4(block4s)
		if err != nil {
			return nil, err
		}

		result = append(result, merged...)
	}

	{
		merged, err := merge6(block6s)
		if err != nil {
			return nil, err
		}

		result = append(result, merged...)
	}

	return result, nil
}

// MergeCIDRs accepts a list of CIDR blocks and merges them into the smallest possible list of CIDRs.
func MergeCIDRs(cidrs []string) ([]string, error) {
	if cidrs == nil {
		return nil, nil
	}
	if len(cidrs) == 0 {
		return make([]string, 0), nil
	}

	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	mergedNets, err := MergeIPNets(networks)
	if err != nil {
		return nil, err
	}

	return ipNets(mergedNets).toCIDRs(), nil
}
