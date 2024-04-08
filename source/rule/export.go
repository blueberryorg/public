package main

import (
	"bytes"
	"fmt"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/osx"
	"github.com/ice-cream-heaven/utils/runtime"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

const (
	checkUrl = "https://www.google.com/generate_204"
)

func (p *Collector) Export() (err error) {
	err = p.Clash()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	err = p.Subconverter()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	err = p.QuanX()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	//err = p.Blue()
	//if err != nil {
	//	log.Panicf("err:%v", err)
	//	return
	//}

	return nil
}

func (p *Collector) Clash() error {

	// var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(p.ExportRules(), func(r rules.Rule) {
		var b bytes.Buffer

		rt, ok := r.Clash()
		if !ok {
			return
		}

		b.WriteString(rt)

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
		err := os.MkdirAll("../../rules/clash/", 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(filepath.Join(runtime.Pwd(), "..", "..", "rules", "clash", key+".list"), []byte(strings.Join(lines, "\n")), 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	err := os.WriteFile("../../rules/clash/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0777)
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

		rt, ok := r.Clash()
		if !ok {
			return
		}
		b.WriteString(rt)

		b.WriteString(",")
		b.WriteString(r.Payload())

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
		err := os.MkdirAll("../../rules/subconverter/", 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/subconverter/%s.list", key), []byte(strings.Join(lines, "\n")), 0777)
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

	rb.WriteString("ruleset=")
	rb.WriteString(Direct.Chinese())
	rb.WriteString(",[]GEOIP,LAN\n")

	rb.WriteString("ruleset=")
	rb.WriteString(Direct.Chinese())
	rb.WriteString(",[]GEOIP,CN\n")

	rb.WriteString("ruleset=规则以外,[]FINAL\n")

	// NOTE: 分组
	rb.WriteString("\n")

	pie.Each(AllRuleType, func(s RuleType) {
		rb.WriteString("custom_proxy_group=")
		rb.WriteString(s.Chinese())
		rb.WriteString("`select")

		switch s {
		case Select:
			rb.WriteString("`select`.*`")
			rb.WriteString(checkUrl)
			rb.WriteString("`60,,1\n")
			return

		case UrlLatency:
			rb.WriteString("`url-test`.*`")
			rb.WriteString(checkUrl)
			rb.WriteString("`60,,1\n")
			return

		case Available:
			rb.WriteString("`fallback`.*`")
			rb.WriteString(checkUrl)
			rb.WriteString("`60,,1\n")
			return

		case RoundRobin:
			rb.WriteString("`load-balance`.*`")
			rb.WriteString(checkUrl)
			rb.WriteString("`60,,1\n")
			return

		}

		pie.Each(s.SubRule(), func(sub RuleType) {
			rb.WriteString("`[]")
			rb.WriteString(sub.Provider())
		})

		switch s.TagRegex() {
		case "":
		case AllProxy:
			rb.WriteString("`.*")
		default:
			rb.WriteString("`")
			rb.WriteString(s.TagRegex())
		}

		rb.WriteString("`\n")
	})

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

			err = os.WriteFile("../../rules/subconverter/clash.yml", buf, 0777)
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}
		}
	}

	// NOTE: quanx
	{
		rb.WriteString("quanx_rule_base=")
		rb.WriteString("https://cdn.jsdelivr.net/gh/blueberryorg/public@master/rules/quanx/quan.conf\n")

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

	err = os.WriteFile("../../rules/subconverter/blueberry.ini", rb.Bytes(), 0777)
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

		rt, ok := r.QuanX()
		if !ok {
			return
		}

		b.WriteString(rt)

		b.WriteString(",")
		b.WriteString(r.Payload())
		b.WriteString(",")

		b.WriteString(r.Adapter())

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], b.String())
	})

	rb := log.GetBuffer()
	defer log.PutBuffer(rb)

	// NOTE: general
	rb.WriteString("[general]")
	rb.WriteString("\n")
	rb.WriteString("\n")

	rb.WriteString("resource_parser_url=https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/resource-parser.js\n")
	rb.WriteString("geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://cdn.jsdelivr.net/gh/limbopro/QuantumultX@master/Scripts/IP_API.js\n")

	rb.WriteString("excluded_routes=192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8\n")
	rb.WriteString("network_check_url=http://connect.rom.miui.com/generate_204, http://connectivitycheck.platform.hicloud.com/generate_204\n")
	rb.WriteString("profile_img_url=https://yattazen.com/favicon.ico\n")
	rb.WriteString("server_check_timeout=2000\n")

	// NOTE: dns
	rb.WriteString("\n[dns]\n")
	rb.WriteString("no-ipv6\n")
	rb.WriteString("server=119.29.29.29\n")
	rb.WriteString("server=223.5.5.5\n")
	rb.WriteString("server=/*.taobao.com/223.5.5.5\n")
	rb.WriteString("server=/*.tmall.com/223.5.5.5\n")
	rb.WriteString("server=/*.alipay.com/223.5.5.5\n")
	rb.WriteString("server=/*.alicdn.com/223.5.5.5\n")
	rb.WriteString("server=/*.aliyun.com/223.5.5.5\n")
	rb.WriteString("server=/*.jd.com/119.28.28.28\n")
	rb.WriteString("server=/*.qq.com/119.28.28.28\n")
	rb.WriteString("server=/*.tencent.com/119.28.28.28\n")
	rb.WriteString("server=/*.weixin.com/119.28.28.28\n")
	rb.WriteString("server=/*.bilibili.com/119.29.29.29\n")
	rb.WriteString("server=/hdslb.com/119.29.29.29\n")
	rb.WriteString("server=/*.163.com/119.29.29.29\n")
	rb.WriteString("server=/*.126.com/119.29.29.29\n")
	rb.WriteString("server=/*.126.net/119.29.29.29\n")
	rb.WriteString("server=/*.127.net/119.29.29.29\n")
	rb.WriteString("server=/*.netease.com/119.29.29.29\n")
	rb.WriteString("server=/*.mi.com/119.29.29.29\n")
	rb.WriteString("server=/*.xiaomi.com/119.29.29.29\n")
	rb.WriteString("address=/mtalk.google.com/108.177.125.188\n")

	if osx.IsDir("../../rules/quanx/") {
		err := os.RemoveAll("../../rules/quanx/")
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	if !osx.IsDir("../../rules/quanx/") {
		err := os.MkdirAll("../../rules/quanx/", 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/quanx/%s.list", key), []byte(strings.Join(lines, "\n")), 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	rb.WriteString("\n[policy]\n")
	pie.Each(AllRuleType, func(s RuleType) {
		switch s {
		case Select:
			rb.WriteString("static")

		case UrlLatency:
			rb.WriteString("url-latency-benchmark")

		case Available:
			rb.WriteString("available")

		case RoundRobin:
			rb.WriteString("round-robin")

		default:
			rb.WriteString("static")
		}

		rb.WriteString("=")
		rb.WriteString(s.Chinese())

		pie.Each(s.SubRule(), func(sub RuleType) {
			rb.WriteString(", ")
			rb.WriteString(sub.Provider())
		})

		switch s.TagRegex() {
		case "":
			// do nothing

		default:
			rb.WriteString(", server-tag-regex=")
			rb.WriteString(s.TagRegex())
		}

		rb.WriteString(", check-interval=60, tolerance=10\n")
	})

	rb.WriteString("static=")
	rb.WriteString("未命中, ")
	rb.WriteString(Proxy.Chinese())
	rb.WriteString(", REJECT, 故障转移, 最低延时, 负载均衡, 手动选择, DIRECT")
	rb.WriteString("\n")

	rb.WriteString("\n[server_remote]\n")

	rb.WriteString("\n[rewrite_remote]\n")

	rb.WriteString("\n[server_local]\n")

	rb.WriteString("\n[rewrite_local]\n")

	rb.WriteString("\n[http_backend]\n")
	rb.WriteString("https://cdn.jsdelivr.net/gh/chavyleung/scripts@master/chavy.box.js, host=boxjs.com, tag=BoxJS, path=^/, enabled=false\n")

	rb.WriteString("\n[filter_local]\n")
	rb.WriteString("ip-cidr, 180.76.76.200/32, reject\n")
	rb.WriteString("ip-cidr, 10.0.0.0/8, direct\n")
	rb.WriteString("ip-cidr, 127.0.0.0/8, direct\n")
	rb.WriteString("ip-cidr, 172.16.0.0/12, direct\n")
	rb.WriteString("ip-cidr, 192.168.0.0/16, direct\n")
	rb.WriteString("ip-cidr, 224.0.0.0/24, direct\n")
	rb.WriteString("ip-cidr, 182.254.116.0/24, direct\n")
	rb.WriteString("final, 未命中\n")

	rb.WriteString("\n[task_local]\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/getsomecat/Qx@main/Net_Speed.js, tag=网速查询, img-url=bolt.square.fill.system, enabled=true\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/streaming-ui-check.js, tag=媒体解锁查询, img-url=play.circle.system, enabled=true\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/traffic-check.js, tag=策略流量查询, img-url=arrow.up.arrow.down.circle.system, enabled=true\n")

	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/geo_location.js, tag=地理位置查询, img-url=location.circle.system, enabled=true\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/switch-check-google.js, tag=谷歌送中查询, img-url=drop.circle.system, enabled=true\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/I-am-R-E/QuantumultX@main/TaskLocal/NeteaseMusicUnlockCheck.js, tag=网易音乐查询, img-url=lock.circle.system, enabled=true\n")

	rb.WriteString("# > 代理链路检测\n")
	rb.WriteString("event-interaction https://cdn.jsdelivr.net/gh/I-am-R-E/Functional-Store-Hub@Master/NodeLinkCheck/Script/NodeLinkCheck.js, tag=代理链路检测, img-url=link.circle.system, enabled=true\n")

	rb.WriteString("\n[filter_remote]\n")
	pie.Each(
		pie.Sort(keys),
		//pie.FilterNot(keys, func(s string) bool {
		//	return RuleType(s) == Direct || RuleType(s) == Reject || RuleType(s) == Privacy
		//}),
		func(s string) {
			rb.WriteString("https://cdn.jsdelivr.net/gh/blueberryorg/public@master/rules/quanx/")
			rb.WriteString(s)

			rb.WriteString(".list, tag=")
			rb.WriteString(RuleType(s).Chinese())

			switch RuleType(s) {
			case Develop, Youtube, Netflix, OpenAI, Game, Disney:
				rb.WriteString(", force-policy=代理选择")
			}

			rb.WriteString(", update-interval=86400, opt-parser=true")

			rb.WriteString("\n")
		},
	)

	rb.WriteString("\n[mitm]\n")
	rb.WriteString("force_sni_domain_name = false\n")

	err := os.WriteFile("../../rules/quanx/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0777)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../rules/quanx/quan.conf", rb.Bytes(), 0777)
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
		err := os.MkdirAll("../../rules/blueberry/", 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	var keys []string
	for key, lines := range ruleMap {
		err := os.WriteFile(fmt.Sprintf("../../rules/blueberry/%s.list", key), []byte(strings.Join(lines, "\n")), 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}

		keys = append(keys, key)
	}

	err := os.WriteFile("../../rules/blueberry/list.keys", []byte(strings.Join(pie.Sort(pie.Unique(keys)), "\n")), 0777)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../rules/blueberry/all.list", []byte(strings.Join(ruleList, "\n")), 0777)
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

	err = os.WriteFile("../../rules/blueberry/proxy_rule.yaml", infoBuf, 0777)
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
