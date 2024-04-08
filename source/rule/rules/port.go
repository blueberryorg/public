package rules

import (
	"fmt"
	"strconv"
)

type PortType int

const (
	PortTypeSrc PortType = iota
	PortTypeDest
)

type Port struct {
	adapter  string
	port     uint64
	portType PortType
}

func (p *Port) Clash() (string, bool) {
	switch p.portType {
	case PortTypeSrc:
		return "SRC-PORT", true
	case PortTypeDest:
		return "DST-PORT", true
	default:
		panic(fmt.Errorf("unknown port type: %v", p.portType))
	}
}

func (p *Port) QuanX() (string, bool) {
	return "", false
}

func (p *Port) RuleType() RuleType {
	switch p.portType {
	case PortTypeSrc:
		return RuleTypeSrcPort
	case PortTypeDest:
		return RuleTypeDstPort
	default:
		panic(fmt.Errorf("unknown port type: %v", p.portType))
	}
}

func (p *Port) Match(metadata *Metadata) bool {
	switch p.portType {
	case PortTypeSrc:
		return metadata.SrcPort == p.port
	case PortTypeDest:
		return metadata.DstPort == p.port
	default:
		panic(fmt.Errorf("unknown port type: %v", p.portType))
	}
}

func (p *Port) Adapter() string {
	return p.adapter
}

func (p *Port) Payload() string {
	return strconv.FormatUint(p.port, 10)
}

func (p *Port) ShouldResolveIP() bool {
	return false
}

func (p *Port) ShouldFindProcess() bool {
	return false
}

func NewPort(port string, adapter string, portType PortType) (*Port, error) {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	return &Port{
		adapter:  adapter,
		port:     p,
		portType: portType,
	}, nil
}
