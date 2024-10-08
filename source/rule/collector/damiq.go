package collector

import (
	"bytes"
	_ "embed"
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
	"path/filepath"
	"strings"
	"time"
)

type DaMiQ struct {
}

func (p *DaMiQ) Download(path string) ([]byte, error) {
	resp, err := client.R().
		SetHeaders(map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		}).
		Get("https://www.dmxqn3v.com/")
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

//go:embed damiq.urls
var damiqUrls string

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

	pie.Each(strings.Split(damiqUrls, "\n"), func(s string) {
		s = strings.TrimSpace(s)

		if s == "" {
			return
		}

		u, err := url.Parse(s)
		if err != nil {
			//log.Errorf("err:%v", err)
			return
		}

		host := u.Hostname()

		switch filepath.Ext(u.Path) {
		case ".m3u8", ".ts",
			".webp":
			if idx := strings.Index(host, "."); idx > 5 {
				host = host[idx+1:]
			}

		case ".ico":

		default:
			return
		}

		rs = append(rs, rules.NewDomainSuffix(host, tag))
		rs = append(rs, rules.NewDomain(host, tag))
	})

	return rs
}

func (p *DaMiQ) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Day
}

func NewDaMiQ() *DaMiQ {
	return &DaMiQ{}
}
