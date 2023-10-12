package main

import (
	"fmt"
	"github.com/blueberryorg/public/source/rule/rules"
	"sync"
)

var cache = NewRuleCache()

type RuleCache struct {
	m sync.Map
}

func NewRuleCache() *RuleCache {
	return &RuleCache{}
}

func (p *RuleCache) Freq(r rules.Rule) bool {
	key := fmt.Sprintf("%d-,%s", r.RuleType(), r.Payload())

	_, ok := p.m.Load(key)
	if ok {
		return true
	}

	p.m.Store(key, true)

	return false
}
