package rules_test

import (
	"github.com/blueberryorg/public/source/rule/rules"
	"testing"
)

func TestMerge(t *testing.T) {
	m := rules.NewCIDRMerge()

	m.AddCIDR("192.168.1.1/24")
	// m.AddCIDR("192.168.1.1/25")

	m.AddCIDR("1.1.1.1/24")

	result, err := m.Merge()
	if err != nil {
		t.Errorf("err:%v", err)
		return
	}
	t.Log(result)
}
