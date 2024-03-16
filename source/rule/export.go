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

	// var ruleList []string
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

	err := os.WriteFile("../../rules/clash/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) Subconverter() (err error) {
	const baseUrl = "https://cdn.jsdelivr.net/gh/blueberryorg/public@master/rules/subconverter/"
	// const baseUrl = "https://raw.githubusercontent.com/blueberryorg/public/master/rules/subconverter/"

	rb := log.GetBuffer()
	defer log.PutBuffer(rb)

	rb.WriteString("[custom]")
	rb.WriteString("\n")

	rb.WriteString("enable_rule_generator=true\n")
	rb.WriteString("overwrite_original_rules=true\n")
	rb.WriteString("skip_cert_verify_flag=false")
	rb.WriteString("udp_flag=true")
	rb.WriteString("tcp_fast_open_flag=true")

	// clashBypass := log.GetBuffer()
	// defer log.PutBuffer(clashBypass)
	//
	// clashBypass.WriteString("cfw-bypass:\n")

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

		// switch r.Adapter() {
		// case Direct.String():
		//	switch r.RuleType() {
		//	case rules.RuleTypeDomain:
		//		clashBypass.WriteString(`    - "`)
		//		clashBypass.WriteString(r.Payload())
		//		clashBypass.WriteString(`"`)
		//		clashBypass.WriteString("\n")
		//
		//	case rules.RuleTypeDomainSuffix:
		//		clashBypass.WriteString(`    - "*.`)
		//		clashBypass.WriteString(r.Payload())
		//		clashBypass.WriteString(`"`)
		//		clashBypass.WriteString("\n")
		//
		//	case rules.RuleTypeDomainKeyword:
		//		clashBypass.WriteString(`    - "*.`)
		//		clashBypass.WriteString(r.Payload())
		//		clashBypass.WriteString(`.*"`)
		//		clashBypass.WriteString("\n")
		//	}
		// }

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

		rb.WriteString(baseUrl)
		rb.WriteString(key)
		rb.WriteString(".list")
		rb.WriteString("\n")
	}

	rb.WriteString("ruleset=DIRECT,[]GEOIP,LAN\n")
	rb.WriteString("ruleset=DIRECT,[]GEOIP,CN\n")
	rb.WriteString("ruleset=规则以外,[]FINAL\n")

	// NOTE: 分组
	rb.WriteString("\n")

	rb.WriteString("custom_proxy_group=")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`select`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`\n")

	rb.WriteString("custom_proxy_group=手动选择`select`.*`https://www.google.com/generate_204`120,,2\n")
	rb.WriteString("custom_proxy_group=故障转移`fallback`.*`https://www.google.com/generate_204`60,,1\n")
	rb.WriteString("custom_proxy_group=负载均衡`load-balance`.*`https://www.google.com/generate_204`60,,1\n")
	rb.WriteString("custom_proxy_group=自动选择`url-test`.*`https://www.google.com/generate_204`60,,1\n")

	pie.Each(
		pie.FilterNot(keys, func(s string) bool {
			return RuleType(s) == Direct || RuleType(s) == Reject || RuleType(s) == Privacy
		}),
		func(s string) {
			rb.WriteString("custom_proxy_group=")
			rb.WriteString(RuleType(s).Chinese())

			switch s {
			case Netflix.String():
				rb.WriteString("`select`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`([nN]etflix|NF|奈飞|🇳)`\n")

			case OpenAI.String():
				rb.WriteString("`select`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`([oO]pen[aA][iI]|[Cc]hat[Gg][Pp][Tt]|🇴)`\n")

			case Youtube.String():
				rb.WriteString("`select`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`([Yy]outu[Bb]e|🇾)`\n")

			case Disney.String():
				rb.WriteString("`select`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`([Dd]isney|迪士尼|🇩)`\n")

			case BiliBili.String():
				rb.WriteString("`select`[]DIRECT`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]REJECT`([Dd]isney|迪士尼|🇩)`\n")

			case IQiyi.String():
				rb.WriteString("`select`[]DIRECT`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]REJECT`(爱奇艺|[iI][Qq]i[Yy]i)`\n")

			case Privacy.String():
				rb.WriteString("`select`[]REJECT`[]DIRECT`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`)\n")

			default:
				rb.WriteString("`select`[]")
				rb.WriteString(Proxy.Chinese())
				rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`.*`\n")
			}
		},
	)

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

	rb.WriteString("custom_proxy_group=规则以外`select`[]")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString("`[]故障转移`[]自动选择`[]手动选择`[]负载均衡`[]DIRECT`[]REJECT`.*`\n")

	// NOTE: 模版
	rb.WriteString("\n")

	// NOTE: clash
	{
		// https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GeneralClashConfig.yml
		rb.WriteString("clash_rule_base=")
		rb.WriteString(baseUrl)
		rb.WriteString("clash.yml\n")

		// clashBypass.WriteString(`    - "localhost"`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 127.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 10.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.16.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.17.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.18.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.19.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.20.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.21.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.22.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.23.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.24.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.25.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.26.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.27.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.28.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.29.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.30.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 172.31.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - 192.168.*`)
		// clashBypass.WriteString("\n")
		// clashBypass.WriteString(`    - <local>`)
		// clashBypass.WriteString("\n")

		{
			buf, err := os.ReadFile("./tpl/clash.yml")
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}

			// buf = bytes.ReplaceAll(buf, []byte("{{Bypass}}"), clashBypass.Bytes())

			err = os.WriteFile("../../rules/subconverter/clash.yml", buf, 0666)
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}
		}
	}

	// NOTE: quanx
	{
		rb.WriteString("quanx_rule_base=")
		rb.WriteString(baseUrl)
		rb.WriteString("quanx.conf\n")

		err = osx.Copy("./tpl/quanx.conf", "../../rules/subconverter/quanx.conf")
	}

	// NOTE: 规则
	rb.WriteString("\n")
	rb.WriteString("add_emoji=true\n")
	rb.WriteString("remove_old_emoji=true\n")
	rb.WriteString("\n")
	rb.WriteString("rule=(流量|时间|应急|过期|Bandwidth|expire),🏳️‍🌈\n")
	rb.WriteString("rule=AC,🇦🇨\n")
	rb.WriteString("rule=(AR|阿根廷),🇦🇷\n")
	rb.WriteString("rule=(奥地利|维也纳),🇦🇹\n")
	rb.WriteString("rule=(AU|Australia|Sydney|澳大利亚|悉尼),🇦🇺\n")
	rb.WriteString("rule=BE,🇧🇪\n")
	rb.WriteString("rule=(BR|Brazil|巴西|圣保罗),🇧🇷\n")
	rb.WriteString("rule=(Canada|加拿大|蒙特利尔|温哥华|楓葉|枫叶),🇨🇦\n")
	rb.WriteString("rule=(瑞士|苏黎世),🇨🇭\n")
	rb.WriteString("rule=(DE|Germany|德国|法兰克福|德),🇩🇪\n")
	rb.WriteString("rule=丹麦,🇩🇰\n")
	rb.WriteString("rule=ES,🇪🇸\n")
	rb.WriteString("rule=EU,🇪🇺\n")
	rb.WriteString("rule=(Finland|芬兰|赫尔辛基),🇫🇮\n")
	rb.WriteString("rule=(FR|France|法国|巴黎),🇫🇷\n")
	rb.WriteString("rule=(UK|England|UnitedKingdom|英国|英|伦敦),🇬🇧\n")
	rb.WriteString("rule=(HK|HongKong|香港|深港|沪港|呼港|HKT|HKBN|HGC|WTT|CMI|穗港|京港|港),🇭🇰\n")
	rb.WriteString("rule=(Indonesia|印尼|印度尼西亚|雅加达),🇮🇩\n")
	rb.WriteString("rule=(Ireland|爱尔兰|都柏林),🇮🇪\n")
	rb.WriteString("rule=(India|印度|孟买),🇮🇳\n")
	rb.WriteString("rule=(Italy|意大利|米兰),🇮🇹\n")
	rb.WriteString("rule=(JP|Japan|日本|东京|大阪|埼玉|沪日|穗日|川日|中日|泉日|杭日),🇯🇵\n")
	rb.WriteString("rule=(KP|朝鲜),🇰🇵\n")
	rb.WriteString("rule=(KR|Korea|KOR|韩国|首尔|韩|韓),🇰🇷\n")
	rb.WriteString("rule=(MO|Macao|澳门|CTM),🇲🇴\n")
	rb.WriteString("rule=(MY|Malaysia|马来西亚),🇲🇾\n")
	rb.WriteString("rule=(NL|Netherlands|荷兰|阿姆斯特丹),🇳🇱\n")
	rb.WriteString("rule=(PH|Philippines|菲律宾),🇵🇭\n")
	rb.WriteString("rule=(RO|罗马尼亚),🇷🇴\n")
	rb.WriteString("rule=(RU|Russia|俄罗斯|伯力|莫斯科|圣彼得堡|西伯利亚|新西伯利亚|京俄|杭俄),🇷🇺\n")
	rb.WriteString("rule=(沙特|迪拜),🇸🇦\n")
	rb.WriteString("rule=(SE|Sweden),🇸🇪\n")
	rb.WriteString("rule=(SG|Singapore|新加坡|狮城|沪新|京新|泉新|穗新|深新|杭新),🇸🇬\n")
	rb.WriteString("rule=(TH|Thailand|泰国|曼谷),🇹🇭\n")
	rb.WriteString("rule=(TR|Turkey|土耳其|伊斯坦布尔),🇹🇷\n")
	rb.WriteString("rule=(US|America|UnitedStates|美国|美|京美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|沪美),🇺🇲\n")
	rb.WriteString("rule=(VN|越南),🇻🇳\n")
	rb.WriteString("rule=(ZA|南非),🇿🇦\n")
	rb.WriteString("rule=(CN|China|回国|中国|江苏|北京|上海|广州|深圳|杭州|常州|徐州|青岛|宁波|镇江|back|TW|Taiwan|台湾|台北|台中|新北|彰化|CHT|新北|台|HINET),🇨🇳\n")

	// NOTE: 其他
	rb.WriteString("\n")
	rb.WriteString("rename=Test-(.*?)-(.*?)-(.*?)\\((.*?)\\)@\\1\\4x测试线路_自\\2到\\3")
	rb.WriteString("rename=\\(?((x|X)?(\\d+)(\\.?\\d+)?)((\\s?倍率?)|(x|X))\\)?@$1x\n")

	// rb.WriteString("exclude_remarks=\n")

	err = os.WriteFile("../../rules/subconverter/blueberry.ini", rb.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Collector) QuanX() error {
	// var ruleList []string
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

	err := os.WriteFile("../../rules/quanx/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0666)
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

	err := os.WriteFile("../../rules/blueberry/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0666)
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
					Direct.String(),
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
				Name: IQiyi.Chinese(),
				Adapters: []string{
					Direct.String(),
					"代理选择",
					"故障切换",
					"延时最低",
					"手动选择",
					"负载均衡",
				},
				Set: IQiyi.String(),
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
