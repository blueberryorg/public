package main

import (
	"crypto/tls"
	"errors"
	"github.com/andybalholm/brotli"
	"github.com/beefsack/go-rate"
	"github.com/elliotchance/pie/v2"
	"github.com/go-resty/resty/v2"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/json"
	"github.com/ice-cream-heaven/utils/osx"
	"github.com/ice-cream-heaven/utils/unit"
	"net/http"
	"os"
	"strings"
	"time"
)

type Sentences struct {
	Id   string   `json:"id,omitempty"`
	Text string   `json:"text,omitempty"`
	Type string   `json:"type,omitempty"`
	From []string `json:"from,omitempty"`
}

type sentences struct {
	Id         int64  `json:"id"`
	Uuid       string `json:"uuid"`
	Hitokoto   string `json:"hitokoto"`
	Type       string `json:"type"`
	From       string `json:"from"`
	FromWho    string `json:"from_who"`
	Creator    string `json:"creator"`
	CreatorUid int64  `json:"creator_uid"`
	Reviewer   int64  `json:"reviewer"`
	CommitFrom string `json:"commit_from"`
	CreatedAt  string `json:"created_at"`
	Length     int64  `json:"length"`
}

type Categories struct {
	Id        int64     `json:"id"`
	Name      string    `json:"name"`
	Desc      string    `json:"desc"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Path      string    `json:"path"`
}

type Hitokoto struct {
	client *resty.Client

	sentences []*Sentences
	rt        *rate.RateLimiter
}

func (p *Hitokoto) getCategories() ([]*Categories, error) {
	p.rt.Wait()

	log.Infof("get categories")

	var categories []*Categories
	resp, err := p.client.R().SetResult(&categories).Get("categories.json")
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("err:%v", resp.Status())
		return nil, errors.New(resp.Status())
	}

	return categories, nil
}

func (p *Hitokoto) getCategory(path string) ([]*sentences, error) {
	p.rt.Wait()

	log.Infof("get category %s", path)

	var sentences []*sentences
	resp, err := p.client.R().SetResult(&sentences).Get(strings.TrimPrefix(path, "/"))
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		log.Errorf("err:%v", resp.Status())
		return nil, errors.New(resp.Status())
	}

	return sentences, nil
}

func (p *Hitokoto) Load() error {
	buf, err := os.ReadFile("../../sentences/sentences.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		log.Errorf("err:%v", err)
		return err
	}

	err = json.Unmarshal(buf, &p.sentences)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Hitokoto) Update() error {
	if !osx.IsDir("../../sentences") {
		err := os.MkdirAll("../../sentences", os.ModePerm)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
	}

	categories, err := p.getCategories()
	if err != nil {
		return err
	}

	for _, category := range categories {
		sentences, err := p.getCategory(category.Path)
		if err != nil {
			return err
		}

		for _, sentence := range sentences {
			sen := &Sentences{
				Id:   sentence.Uuid,
				Text: sentence.Hitokoto,
				Type: category.Name,
				From: pie.Unique(pie.FilterNot([]string{
					sentence.From,
					sentence.FromWho,
				}, func(s string) bool {
					return s == ""
				})),
			}

			p.sentences = append(p.sentences, sen)
		}
	}

	return nil
}

func (p *Hitokoto) Unique() {
	var sentences []*Sentences

	for _, sentence := range p.sentences {
		if sentence.Text == "" {
			continue
		}

		sentences = append(sentences, sentence)
	}

	p.sentences = sentences
}

func (p *Hitokoto) saveAsJson() error {
	log.Infof("save as json")

	buf, err := json.Marshal(p.sentences)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile("../../sentences/sentences.json", buf, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Hitokoto) saveAsCsv() error {
	log.Infof("save as csv")

	b := log.GetBuffer()
	defer log.PutBuffer(b)

	b.WriteString("id,text,type,from\n")

	for _, sentence := range p.sentences {
		b.WriteString(sentence.Id)
		b.WriteString(",")
		b.WriteString(sentence.Text)
		b.WriteString(",")
		b.WriteString(sentence.Type)
		b.WriteString(",")
		b.WriteString(strings.Join(sentence.From, ";"))
		b.WriteString("\n")
	}

	err := os.WriteFile("../../sentences/sentences.csv", b.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Hitokoto) saveAsSql() error {
	log.Infof("save as sql")

	b := log.GetBuffer()
	defer log.PutBuffer(b)

	b.WriteString("DROP TABLE IF EXISTS `sentences`;\n")
	b.WriteString("CREATE TABLE `sentences` (\n")
	b.WriteString("`id` varchar(64) NOT NULL COMMENT 'ID',\n")
	b.WriteString("`text` text NOT NULL COMMENT '内容',\n")
	b.WriteString("`type` varchar(255) NOT NULL COMMENT '类型',\n")
	b.WriteString("`from` varchar(255) NOT NULL COMMENT '来源',\n")
	b.WriteString("PRIMARY KEY (`id`)\n")
	b.WriteString(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='句子';\n")

	b.WriteString("INSERT INTO `sentences` (`id`, `text`, `type`, `from`) VALUES\n")

	for _, sentence := range p.sentences {
		b.WriteString("(")
		b.WriteString(sentence.Id)
		b.WriteString(",")
		b.WriteString(sentence.Text)
		b.WriteString(",")
		b.WriteString(sentence.Type)
		b.WriteString(",")
		b.WriteString(strings.Join(sentence.From, ";"))
		b.WriteString("),\n")
	}

	err := os.WriteFile("../../sentences/sentences.sql", b.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Hitokoto) saveAsBinary() error {
	log.Infof("save as binary")

	b := log.GetBuffer()
	defer log.PutBuffer(b)

	for _, sentence := range p.sentences {
		b.WriteString(sentence.Text)
		b.WriteString("\n")
	}

	log.Info(unit.FormatSize(int64(b.Len())))

	//// snappy
	//{
	//
	//	log.Info(unit.FormatSize(int64(len(snappy.Encode(nil, b.Bytes())))))
	//}
	//
	//// gzip
	//{
	//	bb := log.GetBuffer()
	//	wr, _ := gzip.NewWriterLevel(bb, 9)
	//	wr.Write(b.Bytes())
	//	wr.Flush()
	//	wr.Close()
	//	log.Info(unit.FormatSize(int64(bb.Len())))
	//	log.PutBuffer(bb)
	//}
	//
	//{
	//	bb := log.GetBuffer()
	//	wr, _ := flate.NewWriter(bb, flate.BestCompression)
	//	wr.Write(b.Bytes())
	//	wr.Flush()
	//	wr.Close()
	//	log.Info(unit.FormatSize(int64(bb.Len())))
	//	log.PutBuffer(bb)
	//}
	//
	//// zlib
	//{
	//	bb := log.GetBuffer()
	//	wr, _ := zlib.NewWriterLevel(bb, 9)
	//	wr.Write(b.Bytes())
	//	wr.Flush()
	//	wr.Close()
	//	log.Info(unit.FormatSize(int64(bb.Len())))
	//	log.PutBuffer(bb)
	//}
	//
	//// lz4
	//{
	//	bb := log.GetBuffer()
	//	wr := lz4.NewWriter(bb)
	//	wr.Apply(lz4.CompressionLevelOption(lz4.Level9))
	//	wr.Write(b.Bytes())
	//	wr.Close()
	//	log.Info(unit.FormatSize(int64(bb.Len())))
	//	log.PutBuffer(bb)
	//}

	// brotli
	bb := log.GetBuffer()
	wr := brotli.NewWriterLevel(bb, 11)
	wr.Write(b.Bytes())
	wr.Close()

	//// zlib
	//{
	//	bb := log.GetBuffer()
	//	wr, _ := zlib.NewWriterLevel(bb, 9)
	//	wr.Write(b.Bytes())
	//	wr.Flush()
	//	wr.Close()
	//	err := os.WriteFile("../../sentences/sentences.zlib", bb.Bytes(), 0666)
	//	if err != nil {
	//		log.Errorf("err:%v", err)
	//		return err
	//	}
	//	log.Info(unit.FormatSize(int64(bb.Len())))
	//	log.PutBuffer(bb)
	//}

	err := os.WriteFile("../../sentences/sentences.bin", bb.Bytes(), 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *Hitokoto) Save() (err error) {
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

	err = p.saveAsBinary()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func NewHitokoto() *Hitokoto {
	return &Hitokoto{
		client: resty.New().
			SetTimeout(time.Minute * 10).
			SetRetryWaitTime(time.Second * 30).
			SetRetryCount(10).
			//SetProxy("http://127.0.0.1:10910").
			SetBaseURL("https://cdn.jsdelivr.net/gh/hitokoto-osc/sentences-bundle@master").
			SetTLSClientConfig(&tls.Config{
				InsecureSkipVerify: true,
			}),

		rt: rate.New(1, time.Second*5),
	}
}

func main() {
	h := NewHitokoto()

	err := h.Load()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	err = h.Update()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	h.Unique()

	err = h.Save()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}
}
