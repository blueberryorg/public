package main

import (
	"bytes"
	"fmt"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/osx"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

func (p *Collector) Clash() error {
	//var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(p.ExportRules(), func(r rules.Rule) {
		var b bytes.Buffer
		switch r.RuleType() {
		case rules.RuleTypeDomain:
			b.WriteString("DOMAIN")
		case rules.RuleTypeDomainSuffix:
			b.WriteString("DOMAIN-SUFFIX")
		case rules.RuleTypeDomainKeyword:
			b.WriteString("DOMAIN-KEYWORD")
		case rules.RuleTypeProcessPath:
			b.WriteString("PROCESS-PATH")
		case rules.RuleTypeProcess:
			b.WriteString("PROCESS-NAME")
		case rules.RuleTypeSrcPort:
			b.WriteString("SRC-PORT")
		case rules.RuleTypeDstPort:
			b.WriteString("DST-PORT")
		case rules.RuleTypeIPCIDR:
			b.WriteString("IP-CIDR")
		case rules.RuleTypeSrcIPCIDR:
			b.WriteString("SRC-IP-CIDR")
		case rules.RuleTypeGEOIP:
			b.WriteString("GEOIP")
		default:
			return
		}

		b.WriteString(",")
		b.WriteString(r.Payload())
		b.WriteString(",")

		b.WriteString(r.Adapter())

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
	})

	if osx.IsDir("../../rules/clash/") {
		err := os.RemoveAll("../../rules/clash/")
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	if !osx.IsDir("../../rules/clash/") {
		err := os.MkdirAll("../../rules/clash/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/clash/%s.list", key), []byte(strings.Join(lines, "\n")), 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	err := os.WriteFile("../../rules/clash/list.keys", []byte(strings.Join(keys, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) QuanX() error {
	//var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(p.ExportRules(), func(r rules.Rule) {
		var b bytes.Buffer

		switch r.RuleType() {
		case rules.RuleTypeDomain:
			b.WriteString("HOST")
		case rules.RuleTypeDomainSuffix:
			b.WriteString("HOST-SUFFIX")
		case rules.RuleTypeDomainKeyword:
			b.WriteString("HOST-KEYWORD")
		case rules.RuleTypeIPCIDR:
			b.WriteString("IP-CIDR")
		case rules.RuleTypeGEOIP:
			b.WriteString("GEOIP")
		default:
			return
		}

		b.WriteString(",")
		b.WriteString(r.Payload())
		b.WriteString(",")

		b.WriteString(r.Adapter())

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
	})

	if osx.IsDir("../../rules/quanx/") {
		err := os.RemoveAll("../../rules/quanx/")
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	if !osx.IsDir("../../rules/quanx/") {
		err := os.MkdirAll("../../rules/quanx/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/quanx/%s.list", key), []byte(strings.Join(lines, "\n")), 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	err := os.WriteFile("../../rules/quanx/list", []byte(strings.Join(keys, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) Blue() error {
	var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(p.ExportRules(), func(r rules.Rule) {
		var b bytes.Buffer
		switch r.RuleType() {
		case rules.RuleTypeDomain:
			b.WriteString("DOMAIN")
		case rules.RuleTypeDomainSuffix:
			b.WriteString("DOMAIN-SUFFIX")
		case rules.RuleTypeDomainKeyword:
			b.WriteString("DOMAIN-KEYWORD")
		case rules.RuleTypeProcessPath:
			b.WriteString("PROCESS-PATH")
		case rules.RuleTypeProcess:
			b.WriteString("PROCESS-NAME")
		case rules.RuleTypeSrcPort:
			b.WriteString("SRC-PORT")
		case rules.RuleTypeDstPort:
			b.WriteString("DST-PORT")
		case rules.RuleTypeIPCIDR:
			b.WriteString("IP-CIDR")
		case rules.RuleTypeSrcIPCIDR:
			b.WriteString("SRC-IP-CIDR")
		case rules.RuleTypeGEOIP:
			b.WriteString("GEOIP")
		default:
			return
		}

		b.WriteString(",")
		b.WriteString(r.Payload())
		b.WriteString(",")

		b.WriteString(r.Adapter())

		ruleList = append(ruleList, b.String())
		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
	})

	if osx.IsDir("../../rules/blueberry/") {
		err := os.RemoveAll("../../rules/blueberry/")
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	if !osx.IsDir("../../rules/blueberry/") {
		err := os.MkdirAll("../../rules/blueberry/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/blueberry/%s.list", key), []byte(strings.Join(lines, "\n")), 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	err := os.WriteFile("../../rules/blueberry/list.keys", []byte(strings.Join(keys, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../rules/blueberry/all.list", []byte(strings.Join(ruleList, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	info := &ProxyRoleConfig{
		Adapters: []*ProxyAdapter{
			{
				Type: "select",
				Name: "代理选择",
				Adapters: []string{
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Proxy,
			},
			{
				Type:    "fallback",
				Name:    "故障切换",
				AddNode: true,
			},
			{
				Type:    "min_delay",
				Name:    "延时最低",
				AddNode: true,
			},
			{
				Type:    "select",
				Name:    "手动选择",
				AddNode: true,
			},
			{
				Type:    "load_balance",
				Name:    "负载均衡",
				AddNode: true,
			},

			{
				Type: "select",
				Name: "Youtube",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Youtube,
			},
			{
				Type: "select",
				Name: "Netflix",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Netflix,
			},
			{
				Type: "select",
				Name: "Disney",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Disney,
			},
			{
				Type: "select",
				Name: "BiliBili",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: BiliBili,
			},

			{
				Type: "select",
				Name: "OpenAI",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: OpenAI,
			},
			{
				Type: "select",
				Name: "Game",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Game,
			},
			{
				Type: "select",
				Name: "Develop",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Develop,
			},

			{
				Type: "select",
				Name: "广告屏蔽",
				Adapters: []string{
					"REJECT",
					"DIRECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Reject,
			},
			{
				Type: "select",
				Name: "隐私保护",
				Adapters: []string{
					"REJECT",
					"DIRECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Privacy,
			},

			{
				Type: "select",
				Name: "国内站点",
				Adapters: []string{
					"DIRECT",
					"REJECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Direct,
			},

			{
				Type: "finial",
				Name: "规则以外",
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
					"DIRECT",
					"REJECT",
				},
			},
		},
		RuleList: keys,
	}

	infoBuf, err := yaml.Marshal(info)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../rules/blueberry/proxy_rule.yaml", infoBuf, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

type ProxyAdapter struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	AddNode bool `json:"add_node,omitempty" yaml:"add_node,omitempty"`

	Adapters []string `json:"adapters,omitempty" yaml:"adapters,omitempty"`

	Set string `json:"set,omitempty" yaml:"set,omitempty"`
}

type ProxyRoleConfig struct {
	Adapters []*ProxyAdapter `json:"adapters,omitempty" yaml:"adapters,omitempty"`

	RuleList []string `json:"rule_list,omitempty" yaml:"rule_list,omitempty"`
}
