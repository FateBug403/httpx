package main

import (
	httpx "github.com/FateBug403/httpx/runner"
	"log"
	"strings"
)

func main() {
	option := httpx.DefaultOptions
	option.HTTPProxy = "socks5://127.0.0.1:10808"
	//option.NoFallbackScheme = true

	//ports :="21,22,23,25,53,80,81,82,83,85,88,110,111,135,139,143,161,443,444,465,500,554,587,888,993,995,1024,1025,1026,1027,1080,1194,1234,1433,1701,1723,1900,2000,2080,2082,2083,2086,2087,2096,2121,2222,3000,3128,3306,3389,4443,4444,4567,5000,5001,5357,5555,5683,5985,7000,7547,7777,8000,8001,8008,8009,8010,8020,8080,8081,8082,8086,8088,8089,8090,8099,8291,8443,8800,8880,8888,8889,9000,9001,9003,9010,9080,9090,9100,9200,9443,9527,9530,9999,10000,10001,12345,20000,49152,52869"
	//ports := "9999"
	//err := option.CustomPorts.Set(ports)
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
	option.InputTargetHost = []string{
		"http://www.example.com/",
	}
	hpx, err := httpx.New(option)
	if err != nil {
		log.Println(err)
	}
	hpx.RunEnumeration(func(r httpx.Result) {
		if r.Err!=nil{
			log.Println(r.Err.Error())
		}else {
			log.Println(r.URL+"指纹为："+strings.Join(r.Technologies,","))
		}
	})
	//hpx.RunAlone("http://www.example.com/", func(r httpx.Result) {
	//	if r.Err!=nil{
	//		log.Println(r.Err.Error())
	//		return
	//	}else {
	//		log.Println(r.URL+"指纹为："+strings.Join(r.Technologies,","))
	//	}
	//
	//})

}