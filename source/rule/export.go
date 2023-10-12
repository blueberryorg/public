package main

import (
	"bytes"
	"fmt"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/osx"
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
	})

	if !osx.IsDir("../../rules/") {
		err := os.MkdirAll("../../rules/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	err := os.WriteFile("../../rules/all.list", []byte(strings.Join(ruleList, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}
