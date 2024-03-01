package rules

import (
	"fmt"
)

type RuleType int

const (
	RuleTypeDomain RuleType = iota
	RuleTypeDomainSuffix
	RuleTypeDomainKeyword
	RuleTypeGEOIP
	RuleTypeIPCIDR
	RuleTypeSrcIPCIDR
	RuleTypeSrcPort
	RuleTypeDstPort
	RuleTypeProcess
	RuleTypeProcessPath
	RuleTypeUserAgent
)

type Rule interface {
	Match(metadata *Metadata) bool

	RuleType() RuleType
	Adapter() string
	Payload() string
}

func ParseRule(tp, payload, target string, params []string) (Rule, error) {
	switch tp {
	case "DOMAIN", "HOST":
		return NewDomain(payload, target), nil
	case "DOMAIN-SUFFIX", "HOST-SUFFIX":
		return NewDomainSuffix(payload, target), nil
	case "DOMAIN-KEYWORD", "HOST-KEYWORD":
		return NewDomainKeyword(payload, target), nil
	case "GEOIP":
		return NewGEOIP(payload, target), nil
	case "IP-CIDR", "IP-CIDR6":
		return NewIPCIDR(payload, target)
	case "SRC-IP-CIDR":
		return NewIPCIDR(payload, target)
	case "SRC-PORT":
		return NewPort(payload, target, PortTypeSrc)
	case "DST-PORT":
		return NewPort(payload, target, PortTypeDest)
	case "PROCESS-NAME":
		return NewProcess(payload, target, true)
	case "PROCESS-PATH":
		return NewProcess(payload, target, false)
	case "USER-AGENT":
		return NewUserAgent(payload, target)
	default:
		return nil, fmt.Errorf("unsupported rule type %s", tp)
	}
}
