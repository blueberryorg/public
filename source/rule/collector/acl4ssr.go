package collector

import (
	"errors"
	"github.com/blueberryorg/public/source/rule/rules"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/xtime"
)

type Acl4SSR struct {
	baseUrl string
}

func NewAclSSr() *Acl4SSR {
	p := &Acl4SSR{
		baseUrl: "https://github.com/ACL4SSR/ACL4SSR/raw/master/",
	}

	return p
}

func (p *Acl4SSR) Download(path string) ([]byte, error) {
	resp, err := client.R().Get(p.baseUrl + path)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("%s %s", p.baseUrl+path, resp.Status())
		return nil, errors.New(resp.Status())
	}

	return resp.Body(), nil
}

func (p *Acl4SSR) ParseBody(tag string, body []byte) (rules []rules.Rule) {
	pie.Each(strings.Split(string(body), "\n"), func(line string) {
		if line == "" {
			return
		}

		if strings.HasPrefix(line, "#") {
			return
		}

		r, err := ParseRules(line + "," + tag)
		if err != nil {
			log.Errorf("parse rule err:%s", line)
			log.Errorf("err:%v", err)
			return
		}

		rules = append(rules, r)
	})

	return
}

func (p *Acl4SSR) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Week
}
