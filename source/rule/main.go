package main

import (
	"fmt"
	"github.com/blueberryorg/public/source/rule/collector"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/ice-cream-heaven/utils/cryptox"
	"github.com/ice-cream-heaven/utils/osx"
	"github.com/pterm/pterm"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ice-cream-heaven/utils/unit"

	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
)

type RuleType string

const (
	Proxy   RuleType = "proxy"
	Direct  RuleType = "direct"
	Reject  RuleType = "reject"
	Privacy RuleType = "privacy"

	// 流媒体
	Youtube  RuleType = "youtube"
	Netflix  RuleType = "netflix"
	Disney   RuleType = "disney"
	BiliBili RuleType = "bilibili"

	OpenAI  RuleType = "openai"
	Game    RuleType = "game"
	Develop RuleType = "develop"
)

func (p RuleType) String() string {
	return string(p)
}

func (p RuleType) Chinese() string {
	switch p {
	case Proxy:
		return "代理选择"
	case Direct:
		return "直接连接"
	case Reject:
		return "拒绝连接"
	case Privacy:
		return "隐私保护"
	case Youtube:
		return "Youtube"
	case Netflix:
		return "Netflix"
	case Disney:
		return "Disney"
	case BiliBili:
		return "哔哩哔哩"
	case OpenAI:
		return "OpenAI"
	case Game:
		return "游戏分流"
	case Develop:
		return "开发专用"
	default:
		panic(fmt.Sprintf("unkown %s", p))
	}
}

const (
	CIDR         = "Cidr"
	ACLSSR       = "AclSSr"
	LOYALSOLDIER = "Loyalsoldier"
	BLACKMATRIX7 = "Blackmatrix7"

	ContentFarm = "content-farm"
)

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
	c.AddHandle(CIDR, collector.NewCidr())
	c.AddHandle(ACLSSR, collector.NewAclSSr())
	c.AddHandle(LOYALSOLDIER, collector.NewLoyalsoldier())
	c.AddHandle(BLACKMATRIX7, collector.NewBlackmatrix7())
	c.AddHandle(ContentFarm, collector.NewContentFarm())

	type ParseRule struct {
		Key  string
		Path string
		Tag  RuleType
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

		// LOYALSOLDIER 代理集合
		{LOYALSOLDIER, "tld-not-cn.txt", Proxy}, // 非中国大陆使用的顶级域名列表

		// 内容农场
		{ContentFarm, "Surge.txt", Reject}, // 内容农场

		// BLACKMATRIX7 直连集合
		{BLACKMATRIX7, "ChinaMax/ChinaMax_Classical.yaml", Direct}, // 国内网站/IP合集
		{BLACKMATRIX7, "Cloud/CloudCN/CloudCN.yaml", Direct},       // 国内云计算规则由
		{BLACKMATRIX7, "Direct/Direct.yaml", Direct},               // 直连规则

		// LOYALSOLDIER 直连集合
		{LOYALSOLDIER, "applications.txt", Direct}, // 需要直连的常见软件列表

		// ACLSSR 直连集合
		{ACLSSR, "Clash/ChinaCompanyIp.list", Direct}, // 国内云服务商
		{ACLSSR, "Clash/ChinaDomain.list", Direct},    // 国内常见网站
		{ACLSSR, "Clash/ChinaMedia.list", Direct},     // 中国媒体列表

		// BLACKMATRIX7 隐私集合
		{BLACKMATRIX7, "Privacy/Privacy_Classical.yaml", Privacy}, // 隐私保护
		{BLACKMATRIX7, "Hijacking/Hijacking.yaml", Privacy},       // 反劫持

		// BLACKMATRIX7 拒绝集合
		{BLACKMATRIX7, "Advertising/Advertising_Classical.yaml", Reject}, // 去广告规则
		{BLACKMATRIX7, "ZhihuAds/ZhihuAds.yaml", Reject},                 // 知乎广告拦截

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
		err = c.Parse(i.Key, i.Path, i.Tag.String())
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

	err = c.Clash()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	err = c.Subconverter()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	err = c.QuanX()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}

	err = c.Blue()
	if err != nil {
		log.Panicf("err:%v", err)
		return
	}
}

type Collector struct {
	CollectorMap map[string]CollectorInter

	rules []rules.Rule
}

func NewCollector() *Collector {
	p := &Collector{
		CollectorMap: map[string]CollectorInter{},

		rules: []rules.Rule{},
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

func (p *Collector) downloadWithCache(key, path string) ([]byte, error) {
	cachePath := filepath.Join("tmp", "cache", cryptox.Sha512(fmt.Sprintf("%s_%s", key, filepath.Base(path))))

	if !osx.IsDir(filepath.Dir(cachePath)) {
		err := os.MkdirAll(filepath.Dir(cachePath), 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}
	}

	var needUp bool
	if !osx.IsFile(cachePath) {
		needUp = true
	} else {
		info, err := os.Stat(cachePath)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		needUp = p.CollectorMap[key].NeedUpdate(info)
	}

	if needUp {
		body, err := p.CollectorMap[key].Download(path)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		err = os.WriteFile(cachePath, body, 0666)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}
	}

	body, err := os.ReadFile(cachePath)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	return body, nil
}

func (p *Collector) downloadWithoutCache(key, path string) ([]byte, error) {
	body, err := p.CollectorMap[key].Download(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	return body, nil
}

func (p *Collector) Parse(key string, path string, tag string) (err error) {
	log.SetTrace(fmt.Sprintf("%s_%s", key, filepath.Base(path)))
	log.Infof("parse for key:%s path:%s tag:%s", key, path, tag)

	body, err := p.downloadWithoutCache(key, path)
	//body, err := p.downloadWithCache(key, path)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	log.Infof("download success for key:%s path:%s tag:%s size:%s", key, path, tag, unit.FormatSize(int64(len(body))))

	ruleList := p.CollectorMap[key].ParseBody(tag, body)

	bar, _ := pterm.DefaultProgressbar.
		WithTotal(len(ruleList)).
		WithShowElapsedTime(true).
		WithElapsedTimeRoundingFactor(time.Second).
		WithMaxWidth(120).
		WithShowCount(true).
		WithShowTitle(true).
		UpdateTitle(fmt.Sprintf("正在处理 %s-%s", key, path)).
		Start()
	defer bar.Stop()

	pie.Each(ruleList, func(r rules.Rule) {
		p.AddRule(r)
		bar.Increment()
	})

	return nil
}

func (p *Collector) AddRule(r rules.Rule) {
	if cache.Freq(r) {
		return
	}

	// 返回 true 表示已经存在，需要丢弃
	var handler func(ri rules.Rule) bool

	switch r.RuleType() {
	case rules.RuleTypeDomain:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeDomain:
				// 完全匹配
				return r.Payload() == ri.Payload()
			case rules.RuleTypeDomainKeyword:
				// 字串串匹配
				return strings.Contains(ri.Payload(), r.Payload())
			default:
				return false
			}
		}
	case rules.RuleTypeDomainSuffix:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeDomain:
				return r.Payload() == ri.Payload()
			case rules.RuleTypeDomainSuffix:
				return strings.Contains(r.Payload(), ri.Payload())
			case rules.RuleTypeDomainKeyword:
				// 字串串匹配
				return strings.Contains(ri.Payload(), r.Payload())
			default:
				return false
			}
		}
	case rules.RuleTypeDomainKeyword:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeDomainKeyword:
				// 字串串匹配
				return strings.Contains(r.Payload(), ri.Payload())
			default:
				return false
			}
		}
	case rules.RuleTypeSrcPort:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeSrcPort:
				// 字串串匹配
				return r.Payload() == ri.Payload()
			default:
				return false
			}
		}
	case rules.RuleTypeDstPort:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeDstPort:
				// 字串串匹配
				return r.Payload() == ri.Payload()
			default:
				return false
			}
		}
	case rules.RuleTypeProcess:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeProcess:
				// 字串串匹配
				return strings.EqualFold(r.Payload(), ri.Payload())
			case rules.RuleTypeProcessPath:
				// 字串串匹配
				return strings.EqualFold(r.Payload(), ri.Payload()) ||
					strings.EqualFold(filepath.Base(ri.Payload()), r.Payload())
			default:
				return false
			}
		}
	case rules.RuleTypeProcessPath:
		handler = func(ri rules.Rule) bool {
			switch ri.RuleType() {
			case rules.RuleTypeProcess:
				// 字串串匹配
				return strings.EqualFold(r.Payload(), ri.Payload()) ||
					strings.EqualFold(filepath.Base(r.Payload()), ri.Payload())
			case rules.RuleTypeProcessPath:
				// 字串串匹配
				return strings.EqualFold(r.Payload(), ri.Payload())
			default:
				return false
			}
		}
	default:
		p.rules = append(p.rules, r)
		return
	}

	if pie.Any(p.rules, handler) {
		return
	}

	p.rules = append(p.rules, r)
}

func (p *Collector) ExportRules() []rules.Rule {
	rs := p.rules
	return rs
}

type CollectorInter interface {
	Download(path string) ([]byte, error)
	ParseBody(tag string, body []byte) (rules []rules.Rule)
	NeedUpdate(info os.FileInfo) bool
}
