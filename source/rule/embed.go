package main

import (
	_ "embed"
	"strings"

	"github.com/elliotchance/pie/v2"
	"github.com/ice-cream-heaven/log"
)

//go:embed before.rule
var before string

//go:embed after.rule
var after string

func (p *Collector) load(text string) error {
	pie.Each(strings.Split(strings.ReplaceAll(text, "\r", ""), "\n"), func(line string) {
		if line == "" {
			return
		}

		if strings.HasPrefix(line, "#") {
			return
		}

		r, err := ParseRules(line)
		if err != nil {
			log.Errorf("parse rule err:%s", line)
			return
		}

		p.AddRule(r)
	})

	return nil
}

func (p *Collector) LoadBefore() error {
	return p.load(before)
}

func (p *Collector) LoadAfter() error {
	return p.load(after)
}
