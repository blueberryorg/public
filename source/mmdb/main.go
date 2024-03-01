package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/unit"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type MMDB struct {
	writer *mmdbwriter.Tree
}

func (p *MMDB) Upload() error {
	client, err := minio.New(
		os.Getenv("ENDPOINT"),
		&minio.Options{
			Creds:  credentials.NewStaticV4(os.Getenv("ACCESSKEY"), os.Getenv("SECRETKEY"), ""),
			Secure: false,
		},
	)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	_, err = client.FPutObject(context.Background(), "blueberry", "public/ice.mmdb", filepath.Join(os.TempDir(), "ice.mmdb"), minio.PutObjectOptions{
		ContentType:        "application/x-mmdb",
		ContentDisposition: "attachment; filename=ice.mmdb",
		CacheControl:       "public, max-age=300",
		NumThreads:         1,
		PartSize:           unit.MB * 10,
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	log.Info("upload success")

	return nil
}

func (p *MMDB) update(path string, logic func(record []string) error) error {
	log.Infof("handle %s", path)

	client := &http.Client{
		Timeout: time.Hour,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("err:%v", resp.StatusCode)
		return errors.New("resp.StatusCode != http.StatusOK")
	}

	var reader *csv.Reader
	switch filepath.Ext(path) {
	case ".csv":
		reader = csv.NewReader(resp.Body)
	case ".gz":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
		defer gr.Close()

		reader = csv.NewReader(gr)

	default:
		log.Errorf("known file type")
		return errors.New("known file type")
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}

			log.Errorf("err:%v", err)
			break
		}

		// log.Infof("handle %s -> %s", record[0], record[1])

		err = logic(record)
		if err != nil {
			log.Errorf("record %v", record)
			log.Errorf("err:%v", err)
			return err
		}
	}

	return nil
}

func (p *MMDB) UpdateASN(writer *mmdbwriter.Tree) (err error) {
	err = p.update("https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-asn/geolite2-asn-ipv4.csv", func(record []string) error {
		return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
			"as_number":       mmdbtype.String("AS" + record[2]),
			"as_organization": mmdbtype.String(record[3]),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.update("https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-asn/geolite2-asn-ipv6.csv", func(record []string) error {
		return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
			"as_number":       mmdbtype.String("AS" + record[2]),
			"as_organization": mmdbtype.String(record[3]),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *MMDB) UpdateAsnCountry(writer *mmdbwriter.Tree) (err error) {
	err = p.update("https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-city/geolite2-city-ipv4.csv.gz", func(record []string) error {
		latitude, _ := strconv.ParseFloat(record[7], 64)
		longitude, _ := strconv.ParseFloat(record[8], 64)
		return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
			"country_code": mmdbtype.String(record[2]),
			"city":         mmdbtype.String(record[5]),
			"latitude":     mmdbtype.Float64(latitude),
			"longitude":    mmdbtype.Float64(longitude),
			"time_zone":    mmdbtype.String(record[9]),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.update("https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-city/geolite2-city-ipv6.csv.gz", func(record []string) error {
		latitude, _ := strconv.ParseFloat(record[7], 64)
		longitude, _ := strconv.ParseFloat(record[8], 64)
		return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
			"country_code": mmdbtype.String(record[2]),
			"city":         mmdbtype.String(record[5]),
			"latitude":     mmdbtype.Float64(latitude),
			"longitude":    mmdbtype.Float64(longitude),
			"time_zone":    mmdbtype.String(record[9]),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *MMDB) UpdateChinaOrg(writer *mmdbwriter.Tree) (err error) {
	update := func(path string, logic func(first, last net.IP) error) error {
		log.Infof("handle %s", path)

		client := &http.Client{
			Timeout: time.Hour,
		}
		defer client.CloseIdleConnections()

		resp, err := client.Get(path)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Errorf("err:%v", resp.StatusCode)
			return errors.New("resp.StatusCode != http.StatusOK")
		}

		reader := bufio.NewScanner(resp.Body)
		reader.Split(bufio.ScanLines)

		for reader.Scan() {
			cidr := reader.Text()

			// 获取 cidr 的开始和结束的IP
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}

			firstIp := ip.Mask(ipNet.Mask)
			lastIp := make(net.IP, len(firstIp))
			copy(lastIp, firstIp)

			for i := range lastIp {
				lastIp[i] |= ^ipNet.Mask[i]
			}

			err = logic(firstIp, lastIp)
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}
		}

		return nil
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cernet.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国教育网"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cernet6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国教育网"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/chinanet.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国电信"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/chinanet6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国电信"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cmcc.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国移动"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cmcc6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国移动"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/drpeng.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("鹏博士"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/drpeng6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("鹏博士"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/unicom.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国联通"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/unicom6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			"country_code":    mmdbtype.String("CN"),
			"as_organization": mmdbtype.String("中国联通"),
		})
	})

	return nil
}

func clone(src mmdbtype.DataType) mmdbtype.Map {
	if src == nil {
		return mmdbtype.Map{}
	}

	if src, ok := src.(mmdbtype.Map); ok {
		dst := make(mmdbtype.Map)
		for k, v := range src {
			dst[k] = v
		}

		// NOTE: 对特殊字段的处理
		asOrganization := func() {
			value, ok := dst["as_organization"]
			if !ok {
				return
			}

			mmdbValue, ok := value.(mmdbtype.String)
			if !ok {
				return
			}

			org := strings.ToLower(string(mmdbValue))
			if strings.Contains(org, "alibaba") {
				dst["as_organization"] = mmdbtype.String("阿里云")
				return
			}
			if strings.Contains(org, "tencent") {
				dst["as_organization"] = mmdbtype.String("腾讯云")
				return
			}

			if strings.Contains(org, "baidu") {
				dst["as_organization"] = mmdbtype.String("百度云")
				return
			}

			if strings.Contains(org, "huawei") {
				dst["as_organization"] = mmdbtype.String("华为云")
				return
			}

			if strings.Contains(org, "amazon") {
				dst["as_organization"] = mmdbtype.String("亚马逊")
				return
			}

			if strings.Contains(org, "microsoft") {
				dst["as_organization"] = mmdbtype.String("微软云")
				return
			}

			if strings.Contains(org, "google") {
				dst["as_organization"] = mmdbtype.String("谷歌云")
				return
			}

			if strings.Contains(org, "cloudflare") {
				dst["as_organization"] = mmdbtype.String("Cloudflare")
				return
			}

			if strings.Contains(org, "fastly") {
				dst["as_organization"] = mmdbtype.String("Fastly")
				return
			}

			if strings.Contains(org, "oracle") {
				dst["as_organization"] = mmdbtype.String("甲骨文")
				return
			}

			if strings.Contains(org, "data communication business group") {
				dst["as_organization"] = mmdbtype.String("中华电信")
				return
			}

			if strings.Contains(org, "ovh") {
				dst["as_organization"] = mmdbtype.String("OVH")
				return
			}

			// log.Warnf("as_organization:%s", org)
		}

		asOrganization()

		return dst
	}

	return mmdbtype.Map{}
}

func (p *MMDB) Update() (err error) {
	p.writer, err = mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType:            "GeoLite2-City",
			Description:             nil,
			IncludeReservedNetworks: false,
			IPVersion:               0,
			Languages:               nil,
			RecordSize:              32,
			DisableMetadataPointers: false,
			Inserter: func(old mmdbtype.DataType) inserter.Func {
				return func(new mmdbtype.DataType) (mmdbtype.DataType, error) {
					dst := clone(old)
					if new == nil {
						return dst, nil
					}

					if val, ok := new.(mmdbtype.Map); ok {
						for k, v := range val {
							dst[k] = v
						}
					} else {
						log.Info(new)
						return nil, errors.New("new is not mmdbtype.Map")
					}
					return dst, nil
				}
			},
		},
	)
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}

	err = p.UpdateASN(p.writer)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.UpdateAsnCountry(p.writer)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.UpdateChinaOrg(p.writer)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	b := log.GetBuffer()
	_, err = p.writer.WriteTo(b)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = os.WriteFile(filepath.Join(os.TempDir(), "ice.mmdb"), b.Bytes(), 0644)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = p.Upload()
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func NewMMDB() *MMDB {
	p := &MMDB{}

	return p
}

func main() {
	_ = os.Setenv("ENDPOINT", os.Args[1])
	_ = os.Setenv("ACCESSKEY", os.Args[2])
	_ = os.Setenv("SECRETKEY", os.Args[3])

	log.Info(os.Getenv("ENDPOINT"))
	log.Info(os.Getenv("ACCESSKEY"))
	log.Info(os.Getenv("SECRETKEY"))

	m := NewMMDB()

	err := m.Update()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}
}

// ln -fds /data/rclone/alist/storage/minio/138.2.116.185/blueberry/public /opt/1panel/apps/minio/minio/data/blueberry/public
