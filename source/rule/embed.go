package main

import (
	_ "embed"
	"github.com/blueberryorg/public/source/rule/cidrmerge"
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

	// 清理无效的规则
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
		default:
			// do nothing
		}

		return true
	})

	// NOTE: 对于连续的IP段进行合并
	{
		cm := cidrmerge.NewCIDRMerge()
		var nr []rules.Rule
		pie.Each(p.rules, func(rule rules.Rule) {
			switch rule.RuleType() {
			case rules.RuleTypeIPCIDR, rules.RuleTypeSrcIPCIDR:
				if !cm.CanMerge(rule.Adapter()) {
					if cm.Len() <= 0 {
						panic("merge error")
					}

					list, err := cm.Merge()
					if err != nil {
						log.Errorf("err:%v", err)
						return
					}

					for _, s := range list {
						r, err := rules.NewIPCIDR(s, cm.Adapter())
						if err != nil {
							log.Errorf("err:%v", err)
							continue
						}

						nr = append(nr, r)
					}

					cm.Clear()
				}

				cm.SetAdapter(rule.Adapter())
				cm.AddCIDR(rule.Payload())
				return

			default:
				if cm.Len() > 0 {
					list, err := cm.Merge()
					if err != nil {
						log.Errorf("err:%v", err)
						list = cm.CIDRs()
						log.Errorf("err:%v", list)
					}

					for _, s := range list {
						r, err := rules.NewIPCIDR(s, cm.Adapter())
						if err != nil {
							log.Errorf("err:%v", err)
							continue
						}

						nr = append(nr, r)
					}

					cm.Clear()
				}
			}

			nr = append(nr, rule)
		})
	}

	// NOTE: 清理多余的配置
	{
		var nr []rules.Rule
		pie.Each(p.rules, func(rule rules.Rule) {
			switch rule.RuleType() {
			case rules.RuleTypeIPCIDR, rules.RuleTypeSrcIPCIDR:
				pp := netip.MustParsePrefix(rule.Payload())

				if pie.Any(nr, func(r rules.Rule) bool {
					if r.RuleType() != rules.RuleTypeIPCIDR {
						return false
					}

					if r.RuleType() != rules.RuleTypeSrcIPCIDR {
						return false
					}

					if netip.MustParsePrefix(r.Payload()).Overlaps(pp) {
						return true
					}

					return false
				}) {
					return
				}

				nr = append(nr, rule)
			default:
				nr = append(nr, rule)
			}
		})
		p.rules = nr
	}

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
