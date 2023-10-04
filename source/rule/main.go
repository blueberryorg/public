package main

import (
	"crypto/tls"
	"fmt"
	"github.com/ice-cream-heaven/utils/osx"
	"github.com/pterm/pterm"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/ice-cream-heaven/utils/unit"

	"github.com/Dreamacro/clash/constant"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
)

const (
	Proxy   = "proxy"
	Direct  = "direct"
	Reject  = "reject"
	Privacy = "privacy"

	// 流媒体
	Youtube  = "youtube"
	Netflix  = "netflix"
	Disney   = "disney"
	BiliBili = "bilibili"

	OpenAI  = "openai"
	Game    = "game"
	Develop = "develop"
)

const (
	CIDR         = "Cidr"
	ACLSSR       = "AclSSr"
	LOYALSOLDIER = "Loyalsoldier"
	BLACKMATRIX7 = "Blackmatrix7"
)

var client = resty.New().
	SetTimeout(time.Minute * 10).
	SetRetryWaitTime(time.Second * 30).
	SetRetryCount(10).
	//SetProxy("http://192.168.1.8:7890").
	SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true,
	})

// https://raw.githubusercontent.com/Jejz168/Clash/main/Jejz.ini

func main() {
	var err error
	start := time.Now()
	defer func() {
		pterm.Success.Printfln("耗时:%v", time.Since(start))
	}()

	log.SetLevel(log.ErrorLevel)
	pterm.Info.Printfln("PID:%d", os.Getpid())

	c := NewCollector()
	c.AddHandle(CIDR, NewCidr())
	c.AddHandle(ACLSSR, NewAclSSr())
	c.AddHandle(LOYALSOLDIER, NewLoyalsoldier())
	c.AddHandle(BLACKMATRIX7, NewBlackmatrix7())

	type ParseRule struct {
		Key  string
		Path string
		Tag  string
	}

	ParseList := []ParseRule{
		// 特殊走直连的
		{BLACKMATRIX7, "Lan/Lan.yaml", Direct}, // 本地局域网地址规则由

		// 特殊分类
		{BLACKMATRIX7, "YouTube/YouTube.yaml", Youtube},            // YouTube
		{BLACKMATRIX7, "YouTubeMusic/YouTubeMusic.yaml", Youtube},  // YouTubeMusic
		{BLACKMATRIX7, "Netflix/Netflix.yaml", Netflix},            // Netflix
		{BLACKMATRIX7, "Disney/Disney.yaml", Disney},               // Disney
		{BLACKMATRIX7, "BiliBili/BiliBili.yaml", BiliBili},         // BiliBili
		{BLACKMATRIX7, "BiliBiliIntl/BiliBiliIntl.yaml", BiliBili}, // BiliBili

		{BLACKMATRIX7, "Game/Game.yaml", Game}, // Game-聚合版

		{BLACKMATRIX7, "OpenAI/OpenAI.yaml", OpenAI}, // OpenAI

		{BLACKMATRIX7, "GitHub/GitHub.yaml", Develop},       // GitHub
		{BLACKMATRIX7, "Developer/Developer.yaml", Develop}, // GitHub

		// 特殊走代理的
		{BLACKMATRIX7, "Telegram/Telegram.yaml", Proxy}, // Telegram

		{BLACKMATRIX7, "Google/Google.yaml", Proxy},         // Google
		{BLACKMATRIX7, "Chromecast/Chromecast.yaml", Proxy}, // Chromecast
		{BLACKMATRIX7, "GoogleFCM/GoogleFCM.yaml", Proxy},   // Google推送

		{BLACKMATRIX7, "Wikipedia/Wikipedia.yaml", Proxy}, // Wikipedia

		{BLACKMATRIX7, "Apple/Apple.yaml", Proxy}, // Apple

		{BLACKMATRIX7, "Microsoft/Microsoft.yaml", Proxy}, // Microsoft
		{BLACKMATRIX7, "Bing/Bing.yaml", Direct},          // Bing

		{BLACKMATRIX7, "Cloudflare/Cloudflare.yaml", Proxy}, // Cloudflare
		{BLACKMATRIX7, "Amazon/Amazon.yaml", Proxy},         // Amazon

		{BLACKMATRIX7, "PayPal/PayPal.yaml", Proxy}, // PayPal

		{BLACKMATRIX7, "Spotify/Spotify.yaml", Proxy},   // Spotify
		{BLACKMATRIX7, "TikTok/TikTok.yaml", Proxy},     // TikTok
		{BLACKMATRIX7, "Niconico/Niconico.yaml", Proxy}, // niconico
		{BLACKMATRIX7, "Pixiv/Pixiv.yaml", Proxy},       // Pixiv

		{BLACKMATRIX7, "Whatsapp/Whatsapp.yaml", Proxy}, // Whatsapp
		{BLACKMATRIX7, "Twitter/Twitter.yaml", Proxy},   // Twitter

		// BLACKMATRIX7 代理集合
		{BLACKMATRIX7, "Global/Global.yaml", Proxy},                           // Global
		{BLACKMATRIX7, "GlobalMedia/GlobalMedia.yaml", Proxy},                 // GlobalMedia
		{BLACKMATRIX7, "GlobalSign/GlobalSign.yaml", Proxy},                   // GlobalSign
		{BLACKMATRIX7, "Proxy/Proxy_Classical.yaml", Proxy},                   // 代理
		{BLACKMATRIX7, "Game/GameDownload/GameDownload.yaml", Proxy},          // 游戏下载
		{BLACKMATRIX7, "Cloud/CloudGlobal/CloudGlobal_Classical.yaml", Proxy}, // 全球云计算规则由

		// BLACKMATRIX7 直连集合
		{BLACKMATRIX7, "ChinaMax/ChinaMax_Classical.yaml", Direct}, // 国内网站/IP合集
		{BLACKMATRIX7, "Cloud/CloudCN/CloudCN.yaml", Direct},       // 国内云计算规则由
		{BLACKMATRIX7, "Direct/Direct.yaml", Direct},               // 直连规则

		// BLACKMATRIX7 隐私集合
		{BLACKMATRIX7, "Privacy/Privacy_Classical.yaml", Privacy}, // 隐私保护
		{BLACKMATRIX7, "Hijacking/Hijacking.yaml", Privacy},       // 反劫持

		// BLACKMATRIX7 拒绝集合
		{BLACKMATRIX7, "Advertising/Advertising_Classical.yaml", Reject}, // 去广告规则
		{BLACKMATRIX7, "ZhihuAds/ZhihuAds.yaml", Reject},                 // 知乎广告拦截

		// LOYALSOLDIER 代理集合
		{LOYALSOLDIER, "tld-not-cn.txt", Proxy}, // 非中国大陆使用的顶级域名列表

		// LOYALSOLDIER 直连集合
		{LOYALSOLDIER, "applications.txt", Direct}, // 需要直连的常见软件列表

		// ACLSSR 直连集合
		{ACLSSR, "Clash/ChinaCompanyIp.list", Direct}, // 国内云服务商
		{ACLSSR, "Clash/ChinaDomain.list", Direct},    // 国内常见网站
		{ACLSSR, "Clash/ChinaMedia.list", Direct},     // 中国媒体列表

		// 国内IP清单
		//{ACLSSR, "Clash/ChinaIp.list", Direct},                                                            // 国内IP https://github.com/17mon/china_ip_list/
		//{CIDR, "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt", Direct},     // 国内IP https://github.com/mayaxcn/china-ip-list
		//
		//{CIDR, "https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt", Direct}, // 国内IP https://github.com/metowolf/iplist
	}

	err = c.LoadBefore()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	for _, i := range ParseList {
		err = c.Parse(i.Key, i.Path, i.Tag)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	err = c.LoadAfter()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	//var ruleList []string
	ruleMap := map[string][]string{}
	pie.Each(c.ExportRules(), func(r constant.Rule) {
		line := func(tag string) string {
			line := fmt.Sprintf("%s,%s,%s", func() string {
				switch r.RuleType() {
				case constant.Domain:
					return "DOMAIN"
				case constant.DomainSuffix:
					return "DOMAIN-SUFFIX"
				case constant.DomainKeyword:
					return "DOMAIN-KEYWORD"
				case constant.ProcessPath:
					return "PROCESS-PATH"
				case constant.Process:
					return "PROCESS-NAME"
				case constant.SrcPort:
					return "SRC-PORT"
				case constant.DstPort:
					return "DST-PORT"
				case constant.IPCIDR:
					return "IP-CIDR"
				case constant.SrcIPCIDR:
					return "SRC-IP-CIDR"
				case constant.GEOIP:
					return "GEOIP"
				default:
					return r.RuleType().String()
				}
			}(), r.Payload(), tag)

			//switch r.RuleType() {
			//case constant.IPCIDR, constant.SrcIPCIDR:
			//	line += ",no-resolve"
			//}

			return line
		}

		//ruleList = append(ruleList, line(r.Adapter()))

		ruleMap[r.Adapter()] = append(ruleMap[r.Adapter()], line(r.Adapter()))
	})

	if osx.IsDir("../../rules/") {
		err = os.RemoveAll("../../rules/")
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	if !osx.IsDir("../../rules/") {
		err = os.MkdirAll("../../rules/", 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	for key, lines := range ruleMap {
		err = os.WriteFile(fmt.Sprintf("../../rules/%s.list", key), []byte(strings.Join(lines, "\n")), 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

}

type Collector struct {
	CollectorMap map[string]CollectorInter

	rules []constant.Rule
}

func NewCollector() *Collector {
	p := &Collector{
		CollectorMap: map[string]CollectorInter{},

		rules: []constant.Rule{},
	}

	err := p.LoadBefore()
	if err != nil {
		log.Panicf("err:%v", err)
		return p
	}

	return p
}

func (p *Collector) AddHandle(k string, c CollectorInter) {
	p.CollectorMap[k] = c
}

func (p *Collector) Parse(key string, path string, tag string) (err error) {
	log.SetTrace(fmt.Sprintf("%s_%s", key, filepath.Base(path)))
	log.Infof("parse for key:%s path:%s tag:%s", key, path, tag)

	//cachePath := filepath.Join("tmp", "cache", cryptox.Sha512(fmt.Sprintf("%s_%s", key, filepath.Base(path))))
	//
	//if !osx.IsDir(filepath.Dir(cachePath)) {
	//	err = os.MkdirAll(filepath.Dir(cachePath), 0777)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//}
	//
	//var needUp bool
	//if !osx.IsFile(cachePath) {
	//	needUp = true
	//} else {
	//	info, err := os.Stat(cachePath)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//
	//	needUp = p.CollectorMap[key].NeedUpdate(info)
	//}
	//
	//if needUp {
	//	body, err := p.CollectorMap[key].Download(path)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//
	//	err = os.WriteFile(cachePath, body, 0666)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//}
	//
	//body, err := os.ReadFile(cachePath)
	//if err != nil {
	//	log.Errorf("err:%v", err)
	//	return err
	//}

	body, err := p.CollectorMap[key].Download(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	log.Infof("download success for key:%s path:%s tag:%s size:%s", key, path, tag, unit.FormatSize(int64(len(body))))

	rules := p.CollectorMap[key].ParseBody(tag, body)

	bar, _ := pterm.DefaultProgressbar.
		WithTotal(len(rules)).
		WithElapsedTimeRoundingFactor(time.Second).
		WithMaxWidth(120).
		WithShowCount(true).
		WithShowTitle(true).
		UpdateTitle(fmt.Sprintf("正在处理 %s-%s", key, path)).
		Start()
	defer bar.Stop()

	pie.Each(rules, func(r constant.Rule) {
		p.AddRule(r)
		bar.Increment()
	})

	return nil
}

func (p *Collector) AddRule(r constant.Rule) {
	if cache.Freq(r) {
		return
	}

	meta := &constant.Metadata{}
	switch r.RuleType() {
	case constant.Domain:
		meta.Host = r.Payload()
	case constant.DomainSuffix:
		meta.Host = r.Payload()
	case constant.DomainKeyword:
		meta.Host = r.Payload()
	case constant.SrcPort:
		port, _ := strconv.ParseUint(r.Payload(), 10, 64)
		meta.SrcPort = constant.Port(port)
	case constant.DstPort:
		port, _ := strconv.ParseUint(r.Payload(), 10, 64)
		meta.DstPort = constant.Port(port)
	case constant.Process:
		meta.ProcessPath = r.Payload()
	case constant.ProcessPath:
		meta.ProcessPath = r.Payload()
	default:
		p.rules = append(p.rules, r)
		return
	}

	if pie.Any(p.rules, func(ri constant.Rule) bool {
		return ri.Match(meta)
	}) {
		return
	}

	p.rules = append(p.rules, r)
}

func (p *Collector) ExportRules() []constant.Rule {
	rs := p.rules
	return rs
}

type CollectorInter interface {
	Download(path string) ([]byte, error)
	ParseBody(tag string, body []byte) (rules []constant.Rule)
	NeedUpdate(info os.FileInfo) bool
}
