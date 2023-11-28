package main

import (
	wappalyzer "github.com/FateBug403/httpx/common/wappalyzer"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	resp, err := http.DefaultClient.Get("http://116.113.33.42:8010/")
	if err != nil {
		log.Fatal(err)
	}
	data, _ := ioutil.ReadAll(resp.Body) // Ignoring error for example
	start := time.Now() // 记录开始时间
	wappalyzerClient, err := wappalyzer.New()
	//err = wappalyzerClient.ImportChunsouFingerDatabase()
	//if err != nil {
	//	return
	//}
	//log.Println(string(data))
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data,"")
	elapsed := time.Since(start) // 计算时间差
	fmt.Println("代码块执行时间:", elapsed)
	fmt.Printf("%v\n", fingerprints)

	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]
}
