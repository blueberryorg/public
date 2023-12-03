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

	err := os.WriteFile("../../rules/clash/list.keys", []byte(strings.Join(pie.Unique(keys), "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) Subconverter() (err error) {
	rb := log.GetBuffer()
	defer log.PutBuffer(rb)

	rb.WriteString("[custom]")
	rb.WriteString("\n")

	rb.WriteString("enable_rule_generator=true\n")
	rb.WriteString("overwrite_original_rules=true\n")

	clashBypass := log.GetBuffer()
	defer log.PutBuffer(clashBypass)

	clashBypass.WriteString("cfw-bypass:\n")

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

		switch r.Adapter() {
		case Direct.String():
			switch r.RuleType() {
			case rules.RuleTypeDomain:
				clashBypass.WriteString(`    - "`)
				clashBypass.WriteString(r.Payload())
				clashBypass.WriteString(`"`)
				clashBypass.WriteString("\n")

			case rules.RuleTypeDomainSuffix:
				clashBypass.WriteString(`    - "*.`)
				clashBypass.WriteString(r.Payload())
				clashBypass.WriteString(`"`)
				clashBypass.WriteString("\n")

			case rules.RuleTypeDomainKeyword:
				clashBypass.WriteString(`    - "*.`)
				clashBypass.WriteString(r.Payload())
				clashBypass.WriteString(`.*"`)
				clashBypass.WriteString("\n")
			}
		}

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
	})

	if osx.IsDir("../../rules/subconverter/") {
		err := os.RemoveAll("../../rules/subconverter/")
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	if !osx.IsDir("../../rules/subconverter/") {
		err := os.MkdirAll("../../rules/subconverter/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/subconverter/%s.list", key), []byte(strings.Join(lines, "\n")), 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	// NOTE: 规则集
	rb.WriteString("\n")
	for _, key := range keys {
		rb.WriteString("ruleset")
		rb.WriteString("=")
		rb.WriteString(RuleType(key).Chinese())
		rb.WriteString(",")

		rb.WriteString("https://cdn.jsdelivr.net/gh/blueberryorg/public@master/rules/")
		rb.WriteString("subconverter")
		rb.WriteString("/")
		rb.WriteString(key)
		rb.WriteString(".list")
		rb.WriteString("\n")
	}

	rb.WriteString("ruleset=DIRECT,[]GEOIP,LAN\n")
	rb.WriteString("ruleset=DIRECT,[]GEOIP,CN\n")
	rb.WriteString("ruleset=PROXY,[]FINAL\n")

	// NOTE: 分组
	rb.WriteString("\n")

	rb.WriteString("custom_proxy_group=")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`select`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`\n")
	pie.Each(
		pie.FilterNot(keys, func(s string) bool {
			return RuleType(s) == Direct || RuleType(s) == Reject || RuleType(s) == Privacy
		}),
		func(s string) {
			rb.WriteString("custom_proxy_group=")
			rb.WriteString(RuleType(s).Chinese())
			rb.WriteString("`select`[]")
			rb.WriteString(Proxy.Chinese())
			rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`\n")
		},
	)

	rb.WriteString("custom_proxy_group=手动选择`select`.*`https://www.google.com/generate_204`180,,2\n")
	rb.WriteString("custom_proxy_group=故障转移`fallback`.*`https://www.google.com/generate_204`180,,2\n")
	rb.WriteString("custom_proxy_group=负载均衡`load-balance`.*`https://www.google.com/generate_204`180,,2\n")
	rb.WriteString("custom_proxy_group=自动选择`url-test`.*`https://www.google.com/generate_204`180,,2\n")

	rb.WriteString("custom_proxy_group=")
	rb.WriteString(Direct.Chinese())
	rb.WriteString("`select`[]DIRECT`[]REJECT`[]")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`\n")

	rb.WriteString("custom_proxy_group=")
	rb.WriteString(Reject.Chinese())
	rb.WriteString("`select`[]REJECT`[]DIRECT`[]")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`\n")

	rb.WriteString("custom_proxy_group=")
	rb.WriteString(Privacy.Chinese())
	rb.WriteString("`select`[]REJECT`[]DIRECT`[]")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`\n")

	// NOTE: 模版
	rb.WriteString("\n")

	// NOTE: clash
	// https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GeneralClashConfig.yml
	rb.WriteString("clash_rule_base=https://cdn.jsdelivr.net/gh/blueberryorg/public@master/rules/subconverter/clash.yml\n")

	clashBypass.WriteString(`    - "localhost"`)
	clashBypass.WriteString(`    - 127.*`)
	clashBypass.WriteString(`    - 10.*`)
	clashBypass.WriteString(`    - 172.16.*`)
	clashBypass.WriteString(`    - 172.17.*`)
	clashBypass.WriteString(`    - 172.18.*`)
	clashBypass.WriteString(`    - 172.19.*`)
	clashBypass.WriteString(`    - 172.20.*`)
	clashBypass.WriteString(`    - 172.21.*`)
	clashBypass.WriteString(`    - 172.22.*`)
	clashBypass.WriteString(`    - 172.23.*`)
	clashBypass.WriteString(`    - 172.24.*`)
	clashBypass.WriteString(`    - 172.25.*`)
	clashBypass.WriteString(`    - 172.26.*`)
	clashBypass.WriteString(`    - 172.27.*`)
	clashBypass.WriteString(`    - 172.28.*`)
	clashBypass.WriteString(`    - 172.29.*`)
	clashBypass.WriteString(`    - 172.30.*`)
	clashBypass.WriteString(`    - 172.31.*`)
	clashBypass.WriteString(`    - 192.168.*`)
	clashBypass.WriteString(`    - <local>`)

	err = osx.Copy("./tpl/clash.yml", "../../rules/subconverter/clash.yml")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = osx.Append("../../rules/subconverter/clash.yml", clashBypass)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// NOTE: 其他
	rb.WriteString("\n")
	rb.WriteString("rename=Test-(.*?)-(.*?)-(.*?)\\((.*?)\\)@\\1\\4x测试线路_自\\2到\\3")
	rb.WriteString("rename=\\(?((x|X)?(\\d+)(\\.?\\d+)?)((\\s?倍率?)|(x|X))\\)?@$1x\n")

	//rb.WriteString("exclude_remarks=\n")

	err = os.WriteFile("../../rules/subconverter/blueberry.ini", rb.Bytes(), 0666)
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

	err := os.WriteFile("../../rules/blueberry/list.keys", []byte(strings.Join(pie.Unique(keys), "\n")), 0666)
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
				Name: Proxy.Chinese(),
				Adapters: []string{
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Proxy.String(),
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
				Name: Youtube.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Youtube.String(),
			},
			{
				Type: "select",
				Name: Netflix.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Netflix.String(),
			},
			{
				Type: "select",
				Name: Disney.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Disney.String(),
			},
			{
				Type: "select",
				Name: BiliBili.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: BiliBili.String(),
			},

			{
				Type: "select",
				Name: OpenAI.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: OpenAI.String(),
			},
			{
				Type: "select",
				Name: Game.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Game.String(),
			},
			{
				Type: "select",
				Name: Develop.Chinese(),
				Adapters: []string{
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Develop.String(),
			},

			{
				Type: "select",
				Name: Reject.Chinese(),
				Adapters: []string{
					"REJECT",
					"DIRECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Reject.String(),
			},
			{
				Type: "select",
				Name: Privacy.String(),
				Adapters: []string{
					"REJECT",
					"DIRECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Privacy.Chinese(),
			},

			{
				Type: "select",
				Name: Direct.Chinese(),
				Adapters: []string{
					"DIRECT",
					"REJECT",
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: Direct.String(),
			},

			{
				Type: "finial",
				Name: "规则以外",
				Adapters: []string{
					Proxy.String(),
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
					Direct.String(),
					Reject.String(),
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
