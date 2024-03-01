package main

import (
	"net"

	"github.com/ice-cream-heaven/log"
	"github.com/projectdiscovery/mapcidr"
)

func Merge(cidrs []string) ([]string, error) {
	var ipNets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Panicf("err:%v", err)
			return nil, err
		}

		ipNets = append(ipNets, ipnet)
	}

	v4s, v6s := mapcidr.CoalesceCIDRs(ipNets)

	var ret []string
	for _, v4 := range v4s {
		ret = append(ret, v4.String())
	}

	for _, v6 := range v6s {
		ret = append(ret, v6.String())
	}

	return ret, nil
}
