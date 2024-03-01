package main

import (
	_ "embed"
	"github.com/blueberryorg/public/source/rule/collector"
	"github.com/blueberryorg/public/source/rule/rules"
	"net/netip"
	"strings"

	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
)

//go:embed before.rule
var before string

//go:embed after.rule
var after string

func (p *Collector) load(text string) error {
	pie.Each(strings.Split(strings.ReplaceAll(text, "\r", ""), "\n"), func(line string) {
		if line == "" {
			return
		}

		if strings.HasPrefix(line, "#") {
			return
		}

		r, err := collector.ParseRules(line)
		if err != nil {
			log.Errorf("parse rule err:%s", line)
			return
		}

		p.AddRule(r)
	})

	return nil
}

func (p *Collector) LoadBefore() (err error) {
	err = p.load(before)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) clear() {
	p.rules = pie.Filter(p.rules, func(rule rules.Rule) bool {
		if rule.Payload() == "" {
			return false
		}

		if rule.Adapter() == "" {
			return false
		}

		switch rule.RuleType() {
		case rules.RuleTypeIPCIDR, rules.RuleTypeSrcIPCIDR:
			_, err := netip.ParsePrefix(rule.Payload())
			if err != nil {
				return false
			}
		}

		return true
	})
}

func (p *Collector) LoadAfter() (err error) {
	err = p.load(after)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	p.clear()

	return nil
}
