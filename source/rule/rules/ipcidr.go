package rules

import (
	"net"
)

type IPCIDR struct {
	ipnet       *net.IPNet
	adapter     string
	isSourceIP  bool
	noResolveIP bool
}

func (i *IPCIDR) RuleType() RuleType {
	if i.isSourceIP {
		return RuleTypeSrcIPCIDR
	}
	return RuleTypeIPCIDR
}

func (i *IPCIDR) Match(metadata *Metadata) bool {
	ip := metadata.DstIP
	if i.isSourceIP {
		ip = metadata.SrcIP
	}
	return ip != nil && i.ipnet.Contains(ip)
}

func (i *IPCIDR) Adapter() string {
	return i.adapter
}

func (i *IPCIDR) Payload() string {
	return i.ipnet.String()
}

func (i *IPCIDR) ShouldResolveIP() bool {
	return !i.noResolveIP
}

func (i *IPCIDR) ShouldFindProcess() bool {
	return false
}

func NewIPCIDR(s string, adapter string) (*IPCIDR, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	ipcidr := &IPCIDR{
		ipnet:   ipnet,
		adapter: adapter,
	}

	return ipcidr, nil
}
