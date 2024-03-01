package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/antchfx/htmlquery"
	"github.com/beefsack/go-rate"
	"github.com/elliotchance/pie/v2"
	"github.com/go-resty/resty/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/json"
	"github.com/ice-cream-heaven/utils/osx"
	"github.com/jpillora/backoff"
	"golang.org/x/net/html"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	baseUrl = "http://www.stats.gov.cn/tjsj/tjbz/tjyqhdmhcxhfdm/2020/"
)

type Area struct {
	Name string `json:"name,omitempty"`
	Code string `json:"code,omitempty"`
	Path string `json:"-"`

	ParentCode string `json:"-"`

	Children map[string]*Area `json:"children,omitempty"`
}

func NewArea(name, code, path, parentCode string) *Area {
	//for strings.HasSuffix(code, "00") {
	//	code = strings.TrimSuffix(code, "00")
	//}

	p := &Area{
		Name:       name,
		Code:       code,
		ParentCode: parentCode,
		Children:   make(map[string]*Area),
	}

	log.Infof("new area %s(%s)", name, p.Code)

	//if path != "" {
	//	path = code
	//	switch len(code) {
	//	case 2:
	//		p.Path = code + ".html"
	//	case 4:
	//		p.Path = code[:2] + "/" + code + ".html"
	//	case 6:
	//		p.Path = code[:2] + "/" + code[2:4] + "/" + code + ".html"
	//	case 8:
	//		p.Path = code[:2] + "/" + code[2:4] + "/" + code[4:6] + "/" + code + ".html"
	//	case 10:
	//		p.Path = code[:2] + "/" + code[2:4] + "/" + code[4:6] + "/" + code[6:8] + "/" + code + ".html"
	//	case 12:
	//		p.Path = code[:2] + "/" + code[2:4] + "/" + code[4:6] + "/" + code[6:8] + "/" + code[8:10] + "/" + code + ".html"
	//
	//	default:
	//		log.Panicf("invalid code %s", code)
	//	}
	//
	//}

	return p
}

type ChinaArea struct {
	client *resty.Client

	Area map[string]*Area

	rt         *rate.RateLimiter
	jitterPool sync.Pool
	jitter     *backoff.Backoff
}

func (p *ChinaArea) loadLocal() error {
	buf, err := os.ReadFile("../../area/china_area_small.json")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = json.Unmarshal(buf, &p.Area)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

// NOTE: 解析首页
func (p *ChinaArea) parseIndex() ([]*Area, error) {
	var err error

	jitter := p.jitterPool.Get().(*backoff.Backoff)
	defer func() {
		jitter.Reset()
		p.jitterPool.Put(jitter)
	}()

	for {
		p.rt.Wait()

		var resp *resty.Response
		var doc *html.Node
		var areas []*Area

		resp, err = p.client.R().
			SetHeaders(map[string]string{
				"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"Accept-Encoding":           "gzip, deflate, br",
				"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
				"Cache-Control":             "max-age=0",
				"Connection":                "keep-alive",
				"Host":                      "www.stats.gov.cn",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Site":            "none",
				"Sec-Fetch-User":            "?1",
				"Upgrade-Insecure-Requests": "1",
			}).
			Get(baseUrl + "index.html")
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		switch resp.StatusCode() {
		case http.StatusOK:

		case http.StatusNotFound:
			log.Panicf("not found index.html")
			return nil, nil

		case http.StatusServiceUnavailable:
			err = errors.New(resp.Status())
			log.Errorf("err:%v, wait retry", resp.Status())
			goto END

		default:
			log.Errorf("err:%v", resp.Status())
			log.Errorf("url is %s", resp.RawResponse.Request.URL)
			return nil, errors.New(resp.Status())
		}

		doc, err = htmlquery.Parse(bytes.NewBuffer(resp.Body()))
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		pie.Each(htmlquery.Find(doc, "/html/body/table[2]/tbody/tr[1]/td/table/tbody/tr[2]/td/table/tbody/tr/td/table/tbody/tr/td/a"), func(node *html.Node) {
			areas = append(areas,
				NewArea(
					htmlquery.InnerText(node),
					strings.TrimSuffix(htmlquery.SelectAttr(node, "href"), ".html"),
					htmlquery.SelectAttr(node, "href"),
					"",
				),
			)
		})

		if len(areas) > 0 {
			return areas, nil
		}

	END:
		sleep := jitter.Duration()
		log.Warnf("sleep %s", sleep)
		time.Sleep(sleep)
	}
}

func (p *ChinaArea) parseSub(root *Area) ([]*Area, error) {
	if root.Path == "" {
		return nil, nil
	}

	jitter := p.jitterPool.Get().(*backoff.Backoff)
	defer func() {
		jitter.Reset()
		p.jitterPool.Put(jitter)
	}()

	//jitter := p.jitterPool.Get().(*backoff.Backoff)
	//defer func() {
	//	jitter.Reset()
	//	p.jitterPool.Put(jitter)
	//}()

	var err error
	for {
		p.rt.Wait()

		var resp *resty.Response
		var doc *html.Node
		var areas []*Area
		var subUrl string

		log.Infof("parse sub %s(%s)", root.Name, root.Path)

		resp, err = p.client.R().
			SetHeaders(map[string]string{
				"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"Accept-Encoding":           "gzip, deflate, br",
				"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
				"Cache-Control":             "max-age=0",
				"Connection":                "keep-alive",
				"Host":                      "www.stats.gov.cn",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Site":            "none",
				"Sec-Fetch-User":            "?1",
				"Upgrade-Insecure-Requests": "1",
			}).
			Get(baseUrl + root.Path)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		switch resp.StatusCode() {
		case http.StatusOK:

		case http.StatusNotFound:
			log.Errorf("not found %s", root.Path)
			goto END

		case http.StatusServiceUnavailable:
			err = errors.New(resp.Status())
			log.Errorf("err:%v, wait retry", resp.Status())
			goto END

		default:
			log.Errorf("err:%v", resp.Status())
			log.Errorf("url is %s", resp.RawResponse.Request.URL)
			return nil, errors.New(resp.Status())
		}

		doc, err = htmlquery.Parse(bytes.NewBuffer(resp.Body()))
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		subUrl = strings.TrimPrefix(resp.RawResponse.Request.URL.String(), baseUrl)

		if strings.LastIndex(subUrl, "/") > 0 {
			subUrl = subUrl[:strings.LastIndex(subUrl, "/")]
		}

		pie.Each(htmlquery.Find(doc, "/html/body/table[2]/tbody/tr[1]/td/table/tbody/tr[2]/td/table/tbody/tr/td/table/tbody/tr"), func(node *html.Node) {
			if strings.HasSuffix(htmlquery.SelectAttr(node, "class"), "head") {
				return
			}

			if htmlquery.FindOne(node, "/td[2]/a") != nil && htmlquery.FindOne(node, "/td[1]/a") != nil {
				areas = append(areas,
					NewArea(
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[2]/a")),
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[1]/a"))[:len(root.Code)+2],
						subUrl+htmlquery.SelectAttr(htmlquery.FindOne(node, "/td[1]/a"), "href"),
						root.Code,
					),
				)
			} else if htmlquery.FindOne(node, "/td[3]") != nil {
				areas = append(areas,
					NewArea(
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[3]")),
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[1]"))[:len(root.Code)+2],
						"",
						root.Code,
					),
				)
			} else if htmlquery.FindOne(node, "/td[1]") != nil && htmlquery.FindOne(node, "/td[2]") != nil {
				areas = append(areas,
					NewArea(
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[2]")),
						htmlquery.InnerText(htmlquery.FindOne(node, "/td[1]"))[:len(root.Code)+2],
						"",
						root.Code,
					),
				)
			} else {
				log.Errorf("invalid node")
				log.Panicf(root.Code)
			}
		})

		if len(areas) > 0 {
			return areas, nil
		}

	END:
		sleep := jitter.Duration()
		log.Warnf("sleep %s", sleep)
		time.Sleep(sleep)
	}
}

func (p *ChinaArea) download() error {
	// NOTE: 获取省
	provinces, err := p.parseIndex()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	for _, province := range provinces {
		p.Area[province.Code] = province
	}

	c := make(chan *Area, 1000000)
	defer close(c)

	var w sync.WaitGroup

	handle := func(area *Area) {
		defer w.Done()

		// NOTE: 获取市
		cities, err := p.parseSub(area)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}

		for _, city := range cities {
			area.Children[city.Code] = city

			w.Add(1)

			c <- city
		}
	}

	for i := 0; i < 20; i++ {
		go func() {
			for {
				area, ok := <-c
				if !ok {
					break
				}

				handle(area)
			}
		}()
	}

	for _, province := range provinces {
		w.Add(1)
		c <- province

		time.Sleep(time.Minute)
	}

	w.Wait()

	//// NOTE: 解析省
	//for _, province := range provinces {
	//	// NOTE: 获取市
	//	cities, err := p.parseSub(province)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//
	//	for _, city := range cities {
	//		province.Children[city.Code] = city
	//	}
	//
	//	// NOTE: 解析市
	//	for _, city := range cities {
	//		// NOTE: 获取县区
	//		counties, err := p.parseSub(city)
	//		if err != nil {
	//			log.Errorf("err:%v", err)
	//			return err
	//		}
	//
	//		for _, county := range counties {
	//			city.Children[county.Code] = county
	//		}
	//
	//		// NOTE: 解析县区
	//		for _, county := range counties {
	//			// NOTE: 获取街道乡镇
	//			towns, err := p.parseSub(county)
	//			if err != nil {
	//				log.Errorf("err:%v", err)
	//				return err
	//			}
	//
	//			for _, town := range towns {
	//				county.Children[town.Code] = town
	//			}
	//
	//			// NOTE: 解析街道乡镇
	//			for _, town := range towns {
	//				// NOTE: 获取村委会居委会
	//				villages, err := p.parseSub(town)
	//				if err != nil {
	//					log.Errorf("err:%v", err)
	//					return err
	//				}
	//
	//				for _, village := range villages {
	//					town.Children[village.Code] = village
	//				}
	//			}
	//		}
	//	}
	//}

	return nil
}

func (p *ChinaArea) downloadFromGithub() (err error) {
	type area struct {
		Code     string  `json:"code"`
		Name     string  `json:"name"`
		Children []*area `json:"children"`
	}

	var areas []*area
	resp, err := p.client.R().SetResult(&areas).Get("https://cdn.jsdelivr.net/gh/modood/Administrative-divisions-of-China@master/dist/pcas-code.json")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("err:%v", resp.Status())
		return errors.New(resp.Status())
	}

	var handle func(root *Area, root2 *area)
	handle = func(root *Area, root2 *area) {
		for _, a := range root2.Children {
			area := NewArea(a.Name, a.Code, "", root2.Code)
			root.Children[a.Code] = area

			handle(area, a)
		}
	}

	for _, a := range areas {
		area := NewArea(a.Name, a.Code, "", "")
		p.Area[a.Code] = area

		handle(area, a)
	}

	return nil
}

func (p *ChinaArea) saveAsJson() error {
	log.Infof("save as json")

	m := map[string]map[string]string{}

	var handle func(root *Area)
	handle = func(root *Area) {
		if _, ok := m[root.Code]; !ok {
			m[root.Code] = map[string]string{}
		}

		for _, area := range root.Children {
			m[root.Code][area.Code] = area.Name

			if len(area.Children) > 0 {
				handle(area)
			}
		}
	}

	for _, province := range p.Area {
		handle(province)
	}

	buf, err := json.Marshal(m)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../area/china_area.json", buf, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *ChinaArea) saveAsCsv() error {
	log.Infof("save as csv")

	b := log.GetBuffer()
	defer log.PutBuffer(b)

	b.WriteString("code,name,parent_code\n")

	var handle func(root *Area)
	handle = func(root *Area) {
		b.WriteString(root.Code)
		b.WriteString(",")
		b.WriteString(root.Name)
		b.WriteString(",")
		b.WriteString(root.ParentCode)
		b.WriteString("\n")

		for _, area := range root.Children {
			handle(area)
		}
	}

	for _, province := range p.Area {
		handle(province)
	}

	err := os.WriteFile("../../area/china_area.csv", b.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *ChinaArea) saveAsSql() error {
	log.Infof("save as sql")

	b := log.GetBuffer()
	defer log.PutBuffer(b)

	b.WriteString("# 中国行政区划表\n")
	b.WriteString("\n")

	b.WriteString("DROP TABLE IF EXISTS `ice_china_area`;\n")
	b.WriteString("CREATE TABLE `ice_china_area` (\n")
	b.WriteString("  `code` varchar(12) NOT NULL COMMENT '行政区划代码',\n")
	b.WriteString("  `name` varchar(64) NOT NULL COMMENT '行政区划名称',\n")
	b.WriteString("  `parent_code` varchar(12) NOT NULL COMMENT '上级行政区划代码',\n")
	b.WriteString("  PRIMARY KEY (`code`)\n")
	b.WriteString(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='中国行政区划表';\n")
	b.WriteString("\n")

	var handle func(root *Area)
	handle = func(root *Area) {
		b.WriteString("INSERT INTO `ice_china_area` (`code`, `name`, `parent_code`) VALUES ('")
		b.WriteString(root.Code)
		b.WriteString("', '")
		b.WriteString(root.Name)
		b.WriteString("', '")
		b.WriteString(root.ParentCode)
		b.WriteString("');\n")

		for _, area := range root.Children {
			handle(area)
		}
	}

	for _, province := range p.Area {
		handle(province)
	}

	err := os.WriteFile("../../area/china_area.sql", b.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *ChinaArea) saveAsSmallJson() error {
	log.Infof("save as small json")

	buf, err := json.Marshal(p.Area)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../area/china_area_small.json", buf, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

// 只保留省市
func (p *ChinaArea) saveAsJsonProvinceCity() error {
	log.Infof("save as small json")

	m := make(map[string]*Area, len(p.Area))

	for _, province := range p.Area {
		m[province.Code] = &Area{
			Name:     province.Name,
			Code:     province.Code,
			Children: make(map[string]*Area, len(province.Children)),
		}

		for _, city := range province.Children {
			m[province.Code].Children[city.Code] = &Area{
				Name: city.Name,
				Code: city.Code,
			}
		}
	}

	buf, err := json.Marshal(m)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../area/china_area_province_city.json", buf, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *ChinaArea) save() (err error) {
	err = p.saveAsJson()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.saveAsCsv()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.saveAsSql()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.saveAsSmallJson()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.saveAsJsonProvinceCity()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func NewChinaArea() *ChinaArea {
	return &ChinaArea{
		client: resty.New().
			SetTimeout(time.Minute * 10).
			SetRetryWaitTime(time.Second * 30).
			SetRetryCount(10).
			//SetProxy("http://127.0.0.1:7890").
			SetTLSClientConfig(&tls.Config{
				InsecureSkipVerify: true,
			}),

		rt: rate.New(1, time.Second*1),
		jitterPool: sync.Pool{
			New: func() interface{} {
				return &backoff.Backoff{
					Min:    time.Second * 3,
					Max:    time.Minute,
					Factor: 2,
					//Jitter: true,
				}
			},
		},
		jitter: &backoff.Backoff{
			Min:    time.Second * 3,
			Max:    time.Minute,
			Factor: 2,
			//Jitter: true,
		},

		Area: make(map[string]*Area),
	}
}

func main() {
	var err error
	a := NewChinaArea()

	if !osx.IsDir("../../area") {
		err = os.RemoveAll("../../area")
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	//a.parseSub(NewArea("北京", "13", "11.html", ""))

	//err = a.download()
	//if err != nil {
	//	log.Errorf("err:%v", err)
	//	return
	//}

	err = a.downloadFromGithub()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	//err = a.loadLocal()
	//if err != nil {
	//	log.Errorf("err:%v", err)
	//	return
	//}

	err = a.save()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}
}
