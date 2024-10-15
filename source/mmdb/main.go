package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/ice-cream-heaven/log"
	"github.com/ice-cream-heaven/utils/anyx"
	"github.com/ice-cream-heaven/utils/cryptox"
	"github.com/ice-cream-heaven/utils/runtime"
	"github.com/ice-cream-heaven/utils/unit"
	"github.com/ice-cream-heaven/utils/xtime"
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

const (
	AsNumber       = "as_number"
	AsOrganization = "as_organization"

	CountryCode = "country_code"
	Country     = "country"
	City        = "city"
	Latitude    = "latitude"
	Longitude   = "longitude"
	TimeZone    = "time_zone"
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

func (p *MMDB) getReader(path string) (io.ReadCloser, error) {
	cachePath := filepath.Join("tmp", cryptox.Md5(path)+filepath.Ext(path))

	stat, err := os.Stat(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("err:%v", err)
			return nil, err
		}
	} else if time.Since(stat.ModTime()) <= xtime.Week {
		file, err := os.Open(cachePath)
		if err != nil {
			log.Errorf("err:%v", err)
			return nil, err
		}

		return NewFileReader(filepath.Base(path), file)
	}

	client := &http.Client{
		Timeout: time.Hour,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("err:%v", resp.StatusCode)
		return nil, errors.New("resp.StatusCode != http.StatusOK")
	}

	file, err := os.OpenFile(cachePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		_ = file.Close()
		log.Errorf("err:%v", err)
		return nil, err
	}
	_ = file.Close()

	file, err = os.Open(cachePath)
	if err != nil {
		log.Errorf("err:%v", err)
		return nil, err
	}

	return NewFileReader(filepath.Base(path), file)
}

func (p *MMDB) update(path string, logic func(record []string) error) error {
	log.Infof("handle %s", path)

	remote, err := p.getReader(path)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	defer remote.Close()

	var reader *csv.Reader
	switch filepath.Ext(path) {
	case ".csv":
		reader = csv.NewReader(remote)
	case ".gz":
		gr, err := gzip.NewReader(remote)
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
			continue
		}
	}

	return nil
}

func (p *MMDB) UpdateSapicsIpLocationDb(writer *mmdbwriter.Tree) (err error) {
	update := func(path string, logic func(record []string) error) error {
		return p.update("https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main"+path, logic)
	}

	updateCountry := func(path string) error {
		return update(path, func(record []string) error {
			return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
				CountryCode: mmdbtype.String(record[2]),
			})
		})
	}

	updateAsn := func(path string) error {
		return update(path, func(record []string) error {
			return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
				AsNumber:       mmdbtype.Uint64(anyx.ToUint64(record[2])),
				AsOrganization: mmdbtype.String(record[3]),
			})
		})
	}

	updateCity := func(path string) error {
		return update(path, func(record []string) error {
			latitude, _ := strconv.ParseFloat(record[7], 64)
			longitude, _ := strconv.ParseFloat(record[8], 64)
			return writer.InsertRange(net.ParseIP(record[0]), net.ParseIP(record[1]), mmdbtype.Map{
				CountryCode: mmdbtype.String(record[2]),
				City:        mmdbtype.String(record[5]),
				Latitude:    mmdbtype.Float64(latitude),
				Longitude:   mmdbtype.Float64(longitude),
				TimeZone:    mmdbtype.String(record[9]),
			})
		})
	}

	// asn-country
	err = updateCountry("/asn-country/asn-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/asn-country/asn-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// asn
	err = updateAsn("/asn/asn-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateAsn("/asn/asn-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// dbip-asn
	err = updateAsn("/dbip-asn/dbip-asn-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateAsn("/dbip-asn/dbip-asn-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// dbip-city
	err = updateCity("/dbip-city/dbip-city-ipv4.csv.gz")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCity("/dbip-city/dbip-city-ipv6.csv.gz")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// dbip-country
	err = updateCountry("/dbip-country/dbip-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/dbip-country/dbip-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// dbip-geo-whois-asn-country
	err = updateCountry("/dbip-geo-whois-asn-country/dbip-geo-whois-asn-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/dbip-geo-whois-asn-country/dbip-geo-whois-asn-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// iptoasn-country
	err = updateCountry("/iptoasn-country/iptoasn-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/iptoasn-country/iptoasn-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// iptoasn-asn
	err = updateAsn("/iptoasn-asn/iptoasn-asn-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateAsn("/iptoasn-asn/iptoasn-asn-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// geo-asn-country
	err = updateCountry("/geo-asn-country/geo-asn-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/geo-asn-country/geo-asn-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// geolite2-geo-whois-asn-country
	err = updateCountry("/geolite2-geo-whois-asn-country/geolite2-geo-whois-asn-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/geolite2-geo-whois-asn-country/geolite2-geo-whois-asn-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// geolite2-country
	err = updateCountry("/geolite2-country/geolite2-country-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}
	err = updateCountry("/geolite2-country/geolite2-country-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	// geolite2-city
	err = updateCity("/geolite2-city/geolite2-city-ipv4.csv.gz")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = updateCity("/geolite2-city/geolite2-city-ipv6.csv.gz")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = updateAsn("/heads/main/geolite2-asn/geolite2-asn-ipv4.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = updateAsn("/geolite2-asn/geolite2-asn-ipv6.csv")
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	return nil
}

func (p *MMDB) UpdateChinaOrg(writer *mmdbwriter.Tree) (err error) {
	update := func(path string, logic func(first, last net.IP) error) error {
		log.Infof("handle %s", path)

		remote, err := p.getReader(path)
		if err != nil {
			log.Errorf("err:%v", err)
			return err
		}
		defer remote.Close()

		reader := bufio.NewScanner(remote)
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

	err = update("https://github.com/mayaxcn/china-ip-list/raw/master/chnroute.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode: mmdbtype.String("CN"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://github.com/mayaxcn/china-ip-list/raw/master/chnroute_v6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode: mmdbtype.String("CN"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cernet.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("Cernet"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cernet6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("Cernet"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/chinanet.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("Chinanet"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/chinanet6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("Chinanet"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cmcc.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("CMCC"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/cmcc6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("CMCC"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	err = update("https://gaoyifan.github.io/china-operator-ip/drpeng.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("DrPeng"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/drpeng6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("DrPeng"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/unicom.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("China Unicom"),
		})
	})

	err = update("https://gaoyifan.github.io/china-operator-ip/unicom6.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode:    mmdbtype.String("CN"),
			AsOrganization: mmdbtype.String("China Unicom"),
		})
	})

	err = update("https://github.com/17mon/china_ip_list/raw/refs/heads/master/china_ip_list.txt", func(first, last net.IP) error {
		return writer.InsertRange(first, last, mmdbtype.Map{
			CountryCode: mmdbtype.String("CN"),
		})
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

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
			value, ok := dst[AsOrganization]
			if !ok {
				return
			}

			mmdbValue, ok := value.(mmdbtype.String)
			if !ok {
				return
			}

			org := strings.ToLower(string(mmdbValue))
			if strings.Contains(org, "alibaba") {
				dst[AsOrganization] = mmdbtype.String("阿里云")
				return
			}
			if strings.Contains(org, "tencent") {
				dst[AsOrganization] = mmdbtype.String("腾讯云")
				return
			}

			if strings.Contains(org, "baidu") {
				dst[AsOrganization] = mmdbtype.String("百度云")
				return
			}

			if strings.Contains(org, "huawei") {
				dst[AsOrganization] = mmdbtype.String("华为云")
				return
			}

			if strings.Contains(org, "amazon") {
				dst[AsOrganization] = mmdbtype.String("亚马逊")
				return
			}

			if strings.Contains(org, "microsoft") {
				dst[AsOrganization] = mmdbtype.String("微软云")
				return
			}

			if strings.Contains(org, "google") {
				dst[AsOrganization] = mmdbtype.String("谷歌云")
				return
			}

			if strings.Contains(org, "cloudflare") {
				dst[AsOrganization] = mmdbtype.String("Cloudflare")
				return
			}

			if strings.Contains(org, "fastly") {
				dst[AsOrganization] = mmdbtype.String("Fastly")
				return
			}

			if strings.Contains(org, "oracle") {
				dst[AsOrganization] = mmdbtype.String("甲骨文")
				return
			}

			if strings.Contains(org, "data communication business group") {
				dst[AsOrganization] = mmdbtype.String("中华电信")
				return
			}

			if strings.Contains(org, "ovh") {
				dst[AsOrganization] = mmdbtype.String("OVH")
				return
			}

			// log.Warnf("as_organization:%s", org)
		}

		asCountry := func() {
			value, ok := dst[CountryCode]
			if !ok {
				return
			}

			mmdbValue, ok := value.(mmdbtype.String)
			if !ok {
				return
			}

			if mmdbValue == "" {
				return
			}

			if v, ok := countryMap[string(mmdbValue)]; ok {
				dst[Country] = mmdbtype.String(v)
			} else {
				panic(fmt.Sprintf("country:%s not found", string(mmdbValue)))
			}
		}

		asOrganization()
		asCountry()

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

	err = p.UpdateSapicsIpLocationDb(p.writer)
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

	err = os.WriteFile(filepath.Join(runtime.Pwd(), "ice.mmdb"), b.Bytes(), 0644)
	if err != nil {
		log.Errorf("err:%v", err)
		return err
	}

	//err = p.Upload()
	//if err != nil {
	//	log.Errorf("err:%v", err)
	//	return err
	//}

	return nil
}

func NewMMDB() *MMDB {
	p := &MMDB{}

	return p
}

func main() {
	//_ = os.Setenv("ENDPOINT", os.Args[1])
	//_ = os.Setenv("ACCESSKEY", os.Args[2])
	//_ = os.Setenv("SECRETKEY", os.Args[3])
	//
	//log.Info(os.Getenv("ENDPOINT"))
	//log.Info(os.Getenv("ACCESSKEY"))
	//log.Info(os.Getenv("SECRETKEY"))

	m := NewMMDB()

	err := m.Update()
	if err != nil {
		log.Errorf("err:%v", err)
		return
	}
}

// ln -fds /data/rclone/alist/storage/minio/138.2.116.185/blueberry/public /opt/1panel/apps/minio/minio/data/blueberry/public
