package rules

import (
	"strings"
)

type DomainKeyword struct {
	keyword string
	adapter string
}

func (p *DomainKeyword) Clash() (string, bool) {
	return "DOMAIN-KEYWORD", true
}

func (p *DomainKeyword) QuanX() (string, bool) {
	return "HOST-KEYWORD", true
}

func (dk *DomainKeyword) RuleType() RuleType {
	return RuleTypeDomainKeyword
}

func (dk *DomainKeyword) Match(metadata *Metadata) bool {
	return strings.Contains(metadata.Host, dk.keyword)
}

func (dk *DomainKeyword) Adapter() string {
	return dk.adapter
}

func (dk *DomainKeyword) Payload() string {
	return dk.keyword
}

func (dk *DomainKeyword) ShouldResolveIP() bool {
	return false
}

func (dk *DomainKeyword) ShouldFindProcess() bool {
	return false
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	return &DomainKeyword{
		keyword: strings.ToLower(keyword),
		adapter: adapter,
	}
}
