package main

import "fmt"

type RuleType string

const (
	Proxy RuleType = "proxy"

	// 节点分流规则
	Select     RuleType = "select"
	UrlLatency RuleType = "url_latency"
	Available  RuleType = "available"
	RoundRobin RuleType = "round_robin"

	Direct  RuleType = "direct"
	Reject  RuleType = "reject"
	Privacy RuleType = "privacy"

	// 流媒体
	Youtube  RuleType = "youtube"
	Netflix  RuleType = "netflix"
	Disney   RuleType = "disney"
	BiliBili RuleType = "bilibili"
	IQiyi    RuleType = "iqiyi"

	OpenAI  RuleType = "openai"
	Game    RuleType = "game"
	Develop RuleType = "develop"
)

var AllRuleType = []RuleType{
	Proxy,
	Select,
	UrlLatency,
	Available,
	RoundRobin,
	Direct,
	Reject,
	Privacy,
	Youtube,
	Netflix,
	Disney,
	BiliBili,
	IQiyi,
	OpenAI,
	Game,
	Develop,
}

func (p RuleType) String() string {
	return string(p)
}

func (p RuleType) Provider() string {
	switch p {
	case Proxy:
		return "代理选择"

	case Select:
		return "手动选择"
	case UrlLatency:
		return "最低延时"
	case Available:
		return "故障转移"
	case RoundRobin:
		return "负载均衡"

	case Direct:
		return "DIRECT"
	case Reject:
		return "REJECT"
	case Youtube:
		return "Youtube"
	case Netflix:
		return "Netflix"
	case Disney:
		return "Disney"
	case BiliBili:
		return "哔哩哔哩"
	case IQiyi:
		return "爱奇艺"
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

func (p RuleType) Chinese() string {
	switch p {
	case Proxy:
		return "代理选择"

	case Select:
		return "手动选择"
	case UrlLatency:
		return "最低延时"
	case Available:
		return "故障转移"
	case RoundRobin:
		return "负载均衡"

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
	case IQiyi:
		return "爱奇艺"
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
	AllProxy = "^.*$"
)

func (p RuleType) TagRegex() string {
	switch p {
	case Proxy:
		return ""

	case Direct:
		return ""

	case Reject:
		return ""

	case Privacy:
		return ""

	case Select:
		return AllProxy

	case UrlLatency:
		return AllProxy

	case Available:
		return AllProxy

	case RoundRobin:
		return AllProxy

	case Youtube:
		return "([Yy]outu[Bb]e|🇾)"

	case Netflix:
		return "([nN]etflix|NF|奈飞|🇳)"

	case OpenAI:
		return "([oO]pen[aA][iI]|[Cc]hat[Gg][Pp][Tt]|🇴)"

	case Disney:
		return "([dD]isney|🇩|迪士尼)"

	case BiliBili:
		return "([bB]ili[Bb]ili|🇧|哔哩哔哩)"

	case IQiyi:
		return "([iI]Qi[Ii]yi|🇮)"

	case Game:
		return AllProxy

	case Develop:
		return AllProxy

	default:
		panic(fmt.Sprintf("unkown %s", p))
	}
}

func (p RuleType) SubRule() []RuleType {
	switch p {
	case Proxy:
		return []RuleType{
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case Select:
		return nil

	case UrlLatency:
		return nil

	case Available:
		return nil

	case RoundRobin:
		return nil

	case Direct:
		return []RuleType{
			Direct,
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Reject,
		}

	case Reject:
		return []RuleType{
			Reject,
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
		}

	case Privacy:
		return []RuleType{
			Reject,
			Proxy,
			Direct,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
		}

	case Youtube:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case Netflix:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case Disney:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case OpenAI:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case Game:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case Develop:
		return []RuleType{
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Direct,
			Reject,
		}

	case BiliBili:
		return []RuleType{
			Direct,
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Reject,
		}

	case IQiyi:
		return []RuleType{
			Direct,
			Proxy,
			Available,
			UrlLatency,
			Select,
			RoundRobin,
			Reject,
		}

	default:
		panic(fmt.Sprintf("unkown %s", p))
	}
}
