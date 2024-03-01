package rules

type UserAgent struct {
	payload string
	target  string
}

func (p *UserAgent) Match(metadata *Metadata) bool {
	panic("implement me")
}

func (p *UserAgent) RuleType() RuleType {
	return RuleTypeUserAgent
}

func (p *UserAgent) Adapter() string {
	return p.target
}

func (p *UserAgent) Payload() string {
	return p.payload
}

func NewUserAgent(payload, target string) (Rule, error) {
	return &UserAgent{payload: payload, target: target}, nil
}
