package rules

import (
	"strings"
)

type Domain struct {
	domain  string
	adapter string
}

func (p *Domain) Clash() (string, bool) {
	return "DOMAIN", true
}

func (p *Domain) QuanX() (string, bool) {
	return "HOST", true
}

func (p *Domain) RuleType() RuleType {
	return RuleTypeDomain
}

func (p *Domain) Match(metadata *Metadata) bool {
	return metadata.Host == p.domain
}

func (p *Domain) Adapter() string {
	return p.adapter
}

func (p *Domain) Payload() string {
	return p.domain
}

func NewDomain(domain string, adapter string) *Domain {
	return &Domain{
		domain:  strings.ToLower(domain),
		adapter: adapter,
	}
}
