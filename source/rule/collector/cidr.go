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

type Cidr struct {
}

func (p *Cidr) Download(path string) ([]byte, error) {
	resp, err := client.R().Get(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("err:%v", err)
		return nil, errors.New(resp.Status())
	}

	return resp.Body(), nil
}

func (p *Cidr) ParseBody(tag string, body []byte) (rules []rules.Rule) {
	pie.Each(strings.Split(string(body), "\n"), func(line string) {
		line = strings.ReplaceAll(line, "\r", "")

		if line == "" {
			return
		}

		r, err := ParseRules("IP-CIDR," + line + "," + tag)
		if err != nil {
			log.Errorf("parse rule err:%s", line)
			log.Errorf("err:%v", err)
			return
		}

		rules = append(rules, r)
	})

	return
}

func NewCidr() *Cidr {
	return &Cidr{}
}

func (p *Cidr) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Week
}
