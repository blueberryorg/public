package collector

import (
	"errors"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/xtime"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

type ContentFarm struct {
	baseUrl string
}

func (p *ContentFarm) Download(path string) ([]byte, error) {
	resp, err := client.R().Get(p.baseUrl + path)
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

func (p *ContentFarm) ParseBody(tag string, body []byte) (rs []rules.Rule) {
	pie.Each(strings.Split(string(body), "\n"), func(line string) {
		if strings.HasPrefix(line, "#") {
			line = strings.TrimPrefix(line, "#")
			_, err := netip.ParseAddr(line)
			if err == nil {
				r, err := rules.NewIPCIDR(line+"/32", tag)
				if err != nil {
					log.Errorf("err:%v", err)
					return
				} else {
					rs = append(rs, r)
				}
			} else {
				rs = append(rs, rules.NewDomain(strings.TrimPrefix(line, "#"), tag))
			}

		} else if strings.HasPrefix(line, ".") {
			rs = append(rs, rules.NewDomainSuffix(line, tag))
		}
	})

	return
}

func (p *ContentFarm) NeedUpdate(info os.FileInfo) bool {
	return time.Since(info.ModTime()) > xtime.Week
}

func NewContentFarm() *ContentFarm {
	p := &ContentFarm{
		baseUrl: "https://cdn.jsdelivr.net/gh/wdmpa/content-farm-list@main/",
	}

	return p
}
