package collector

import (
	"errors"
	"github.com/blueberryorg/public/source/rule/rules"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/xtime"
	"gopkg.in/yaml.v3"
)

type Loyalsoldier struct {
	baseUrl string
}

func (p *Loyalsoldier) Download(path string) ([]byte, error) {
	resp, err := client.R().Get(p.baseUrl + path)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("err:%v", resp.Status())
		return nil, errors.New(resp.Status())
	}

	return resp.Body(), nil
}

func (p *Loyalsoldier) ParseBody(tag string, body []byte) (rules []rules.Rule) {
	var data struct {
		Payload []string `yaml:"payload"`
	}

	err := yaml.Unmarshal(body, &data)
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	pie.Each(data.Payload, func(line string) {
		if strings.HasPrefix(line, "+.") {
			r, err := ParseRules("DOMAIN-SUFFIX," + strings.TrimPrefix(line, "+") + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

		if strings.HasPrefix(line, "*.*.") {
			r, err := ParseRules("DOMAIN-SUFFIX," + strings.TrimPrefix(line, "*.*") + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

		if strings.HasPrefix(line, ".") {
			r, err := ParseRules("DOMAIN-SUFFIX," + line + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

		if strings.Contains(line, ",") {
			r, err := ParseRules(line + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

		_, _, err = net.ParseCIDR(line)
		if err == nil {
			r, err := ParseRules("IP-CIDR," + line + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

		if strings.Contains(line, ".") {
			r, err := ParseRules("DOMAIN," + line + "," + tag)
			if err != nil {
				log.Errorf("parse rule err:%s", line)
				log.Errorf("err:%v", err)
				return
			}

			rules = append(rules, r)
			return
		}

	})

	return
}

func NewLoyalsoldier() *Loyalsoldier {
	return &Loyalsoldier{
		baseUrl: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/",
	}
}

func (p *Loyalsoldier) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Week
}
