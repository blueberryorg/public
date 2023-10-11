package main

import (
	"bytes"
	"fmt"
	"github.com/Dreamacro/clash/constant"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/osx"
	"os"
	"strings"
)

func (p *Collector) Clash() error {
	//var ruleList []string
	ruleMap := map[string][]string{}
	var ruleList []string
	pie.Each(p.ExportRules(), func(r constant.Rule) {
		var b bytes.Buffer
		switch r.RuleType() {
		case constant.Domain:
			b.WriteString("DOMAIN")
		case constant.DomainSuffix:
			b.WriteString("DOMAIN-SUFFIX")
		case constant.DomainKeyword:
			b.WriteString("DOMAIN-KEYWORD")
		case constant.ProcessPath:
			b.WriteString("PROCESS-PATH")
		case constant.Process:
			b.WriteString("PROCESS-NAME")
		case constant.SrcPort:
			b.WriteString("SRC-PORT")
		case constant.DstPort:
			b.WriteString("DST-PORT")
		case constant.IPCIDR:
			b.WriteString("IP-CIDR")
		case constant.SrcIPCIDR:
			b.WriteString("SRC-IP-CIDR")
		case constant.GEOIP:
			b.WriteString("GEOIP")
		default:
			return
		}

		b.WriteString(",")
		b.WriteString(r.Payload())
		b.WriteString(",")

		b.WriteString(r.Adapter())

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
		ruleList = append(ruleList, b.String())
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

	err = os.WriteFile("../../rules/clash/all.list", []byte(strings.Join(ruleList, "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) QuanX() error {
	//var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(p.ExportRules(), func(r constant.Rule) {
		var b bytes.Buffer

		switch r.RuleType() {
		case constant.Domain:
			b.WriteString("HOST")
		case constant.DomainSuffix:
			b.WriteString("HOST-SUFFIX")
		case constant.DomainKeyword:
			b.WriteString("HOST-KEYWORD")
		case constant.IPCIDR:
			b.WriteString("IP-CIDR")
		case constant.GEOIP:
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
