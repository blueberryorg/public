package main

import (
	"fmt"
	"github.com/Dreamacro/clash/constant"
	"sync"
)

var cache = NewRuleCache()

type RuleCache struct {
	m sync.Map
}

func NewRuleCache() *RuleCache {
	return &RuleCache{}
}

func (p *RuleCache) Freq(r constant.Rule) bool {
	key := fmt.Sprintf("%s-,%s", r.RuleType(), r.Payload())

	_, ok := p.m.Load(key)
	if ok {
		return true
	}

	p.m.Store(key, true)

	return false
}
