package cidrmerge

type CIDRMerge struct {
	cidrs   []string
	adapter string
}

func (p *CIDRMerge) AddCIDR(cidr string) {
	p.cidrs = append(p.cidrs, cidr)
}

func (p *CIDRMerge) SetAdapter(adapter string) {
	p.adapter = adapter
}

func (p *CIDRMerge) CanMerge(adapter string) bool {
	if len(p.cidrs) == 0 {
		return true
	}

	return p.adapter == adapter
}

func (p *CIDRMerge) Adapter() string {
	return p.adapter
}

func (p *CIDRMerge) Merge() ([]string, error) {
	return MergeCIDRs(p.cidrs)
}

func (p *CIDRMerge) CIDRs() []string {
	return p.cidrs
}

func (p *CIDRMerge) Clear() {
	p.cidrs = make([]string, 0)

	p.adapter = ""
}

func (p *CIDRMerge) Len() int {
	return len(p.cidrs)
}

func NewCIDRMerge() *CIDRMerge {
	return &CIDRMerge{}
}
