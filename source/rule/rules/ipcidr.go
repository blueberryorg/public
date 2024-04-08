package rules

import (
	"net"
	"net/netip"
)

type IPCIDR struct {
	ipnet       *net.IPNet
	adapter     string
	isSourceIP  bool
	noResolveIP bool
}

func (p *IPCIDR) Clash() (string, bool) {
	return "IP-CIDR", true
}

func (p *IPCIDR) QuanX() (string, bool) {
	if netip.MustParsePrefix(p.Payload()).Addr().Is6() {
		return "IP6-CIDR", true
	} else {
		return "IP-CIDR", true
	}
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
