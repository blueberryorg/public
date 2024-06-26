package rules

import (
	"strings"

	"github.com/Dreamacro/clash/component/mmdb"
)

type GEOIP struct {
	country     string
	adapter     string
	noResolveIP bool
}

func (p *GEOIP) Clash() (string, bool) {
	return "GEOIP", true
}

func (p *GEOIP) QuanX() (string, bool) {
	return "GEOIP", true
}

func (g *GEOIP) RuleType() RuleType {
	return RuleTypeGEOIP
}

func (g *GEOIP) Match(metadata *Metadata) bool {
	ip := metadata.DstIP
	if ip == nil {
		return false
	}

	if strings.EqualFold(g.country, "LAN") {
		return ip.IsPrivate()
	}
	record, _ := mmdb.Instance().Country(ip)
	return strings.EqualFold(record.Country.IsoCode, g.country)
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func (g *GEOIP) ShouldResolveIP() bool {
	return !g.noResolveIP
}

func (g *GEOIP) ShouldFindProcess() bool {
	return false
}

func NewGEOIP(country string, adapter string) *GEOIP {
	geoip := &GEOIP{
		country: country,
		adapter: adapter,
	}

	return geoip
}
