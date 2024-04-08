package collector

import (
	"bytes"
	"errors"
	"github.com/antchfx/htmlquery"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/xtime"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
	"os"
	"time"
)

type DaMiQ struct {
}

func (p *DaMiQ) Download(path string) ([]byte, error) {
	resp, err := client.R().SetHeaders(map[string]string{
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
	}).Get("https://damiq.cc/")
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

func (p *DaMiQ) ParseBody(tag string, body []byte) (rs []rules.Rule) {
	doc, err := htmlquery.Parse(bytes.NewBuffer(body))
	if err != nil {
		log.Panicf("err:%v", err)
		return nil
	}

	pie.Each(htmlquery.Find(doc, `//*[@id="all"]/div/div/div/div/ul/li/div/div[2]/a`), func(node *html.Node) {
		u, err := url.Parse(htmlquery.SelectAttr(node, "href"))
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}

		if u.Hostname() == "t.me" {
			return
		}

		rs = append(rs, rules.NewDomainSuffix(u.Hostname(), tag))
	})

	return rs
}

func (p *DaMiQ) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Week
}

func NewDaMiQ() *DaMiQ {
	return &DaMiQ{}
}
