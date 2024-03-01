package collector

import (
	"fmt"
	"github.com/blueberryorg/public/source/rule/rules"
	"github.com/ice-cream-heaven/log"
	"strings"
)

func ParseRules(line string) (rules.Rule, error) {
	line = strings.ReplaceAll(line, ",no-resolve", "")
	rule := trimArr(strings.Split(line, ","))

	var target string
	var payload string
	var params []string

	switch l := len(rule); {
	case l == 2:
		target = rule[1]
	case l == 3:
		payload = rule[1]
		target = rule[2]
	case l >= 4:
		payload = rule[1]
		target = rule[2]
		params = rule[3:]
	default:
		return nil, fmt.Errorf("rules[%d] [%s] error: %s", 0, line, "invalid rule")
	}

	rule = trimArr(rule)
	params = trimArr(params)

	parsed, err := rules.ParseRule(rule[0], payload, target, params)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	return parsed, nil
}

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}
