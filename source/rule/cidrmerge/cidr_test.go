package cidrmerge_test

import (
	"github.com/blueberryorg/public/source/rule/cidrmerge"
	"testing"
)

func TestMerge(t *testing.T) {
	m := cidrmerge.NewCIDRMerge()

	m.AddCIDR("1.116.116.0/22")
	m.AddCIDR("1.116.216.0/23")
	m.AddCIDR("2402:dfc0:50::/44")

	result, err := m.Merge()
	if err != nil {
		t.Errorf("err:%v", err)
		return
	}
	t.Log(result)
}
