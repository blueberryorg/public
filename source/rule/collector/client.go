package collector

import (
	"crypto/tls"
	"github.com/go-resty/resty/v2"
	"time"
)

var client = resty.New().
	SetTimeout(time.Minute * 10).
	SetRetryWaitTime(time.Second * 30).
	SetRetryCount(10).
	//SetProxy("http://127.0.0.1:7899").
	SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true,
	})
