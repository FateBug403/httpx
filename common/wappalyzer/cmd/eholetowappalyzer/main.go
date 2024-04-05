package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/FateBug403/httpx/common/wappalyzer"
	"github.com/FateBug403/util"
	"log"
	"os"
	"regexp"
	"strings"
)

//go:embed ehole.json
var ehole string

type EholeFinger struct {
	Fingerprint []struct {
		Cms      string   `json:"cms"`
		Method   string   `json:"method"`
		Location string   `json:"location"`
		Keyword  []string `json:"keyword"`
	} `json:"fingerprint"`
}


func main() {
	var err error
	var Fingerprints wappalyzer.Fingerprints
	Fingerprints.Apps = make(map[string]*wappalyzer.Fingerprint)
	var EholeFingerStruct EholeFinger
	err = json.Unmarshal([]byte(ehole), &EholeFingerStruct) // 将指定json文件反序列化到指纹结构体中
	if err != nil {
		return
	}

	//locations:= make(map[string]bool)
	//method :=make(map[string]bool)
	//for _, fingerprint := range EholeFingerStruct.Fingerprint {
	//	if len(fingerprint.Keyword)>1 && fingerprint.Location=="title"{
	//		log.Println(fingerprint.Keyword)
	//	}
	//
	//	if _,ok:=locations[fingerprint.Location];!ok{
	//		locations[fingerprint.Location]=true
	//	}
	//	if _,ok:=locations[fingerprint.Method];!ok{
	//		method[fingerprint.Method]=true
	//	}
	//}
	//for value,_:=range locations{
	//	log.Println("location:"+value)
	//}
	//for value,_:=range method{
	//	log.Println("method:"+value)
	//}

	for _, fingerprint := range EholeFingerStruct.Fingerprint {
		if _,ok:=Fingerprints.Apps[fingerprint.Cms];!ok{
			Fingerprints.Apps[fingerprint.Cms] = &wappalyzer.Fingerprint{}
		}
		if fingerprint.Location =="body" && fingerprint.Method=="keyword" {
			if len(fingerprint.Keyword)>1{
				var keywordtmp []string
				for _,value := range fingerprint.Keyword{
					keywordtmp = append(keywordtmp,regexp.QuoteMeta(value))
				}
				keyword := "(?si).*"+strings.Join(keywordtmp,".*")+".*"
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
					Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,keyword)
				}
			}else {
				keyword :="(?i)"+regexp.QuoteMeta(fingerprint.Keyword[0])
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
					Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,keyword)
				}
			}
			//for _,v := range fingerprint.Keyword{
			//	if v!=""{
			//		keyword :="(?i)"+regexp.QuoteMeta(v)
			//		if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
			//			Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,"(?i)"+regexp.QuoteMeta(v))
			//		}
			//
			//	}
			//}
		}else if fingerprint.Location =="header" && fingerprint.Method=="keyword" {
			if len(fingerprint.Keyword)>1{
				var keywordtmp []string
				for _,value := range fingerprint.Keyword{
					keywordtmp = append(keywordtmp,regexp.QuoteMeta(value))
				}
				keyword := "(?si).*"+strings.Join(keywordtmp,".*")+".*"
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].HeadersRaw){
					Fingerprints.Apps[fingerprint.Cms].HeadersRaw = append(Fingerprints.Apps[fingerprint.Cms].HeadersRaw,keyword)
				}
			}else {
				keyword :="(?i)"+regexp.QuoteMeta(fingerprint.Keyword[0])
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].HeadersRaw){
					Fingerprints.Apps[fingerprint.Cms].HeadersRaw = append(Fingerprints.Apps[fingerprint.Cms].HeadersRaw,keyword)
				}
			}
			//for _,v := range fingerprint.Keyword{
			//	if v!=""{
			//		keyword := "(?i)"+regexp.QuoteMeta(v)
			//		if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].HeadersRaw){
			//			Fingerprints.Apps[fingerprint.Cms].HeadersRaw = append(Fingerprints.Apps[fingerprint.Cms].HeadersRaw,keyword)
			//		}
			//	}
			//}
		}else if fingerprint.Method=="faviconhash" && fingerprint.Location=="body" {
			for _,v := range fingerprint.Keyword{
				if v!=""{
					keyword := regexp.QuoteMeta(v)
					if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].IconHash){
						Fingerprints.Apps[fingerprint.Cms].IconHash = append(Fingerprints.Apps[fingerprint.Cms].IconHash,keyword)
					}
				}
			}
		}else if fingerprint.Location == "title" && fingerprint.Method=="keyword"{
			if len(fingerprint.Keyword)>1{
				var keywordtmp []string
				for _,value := range fingerprint.Keyword{
					keywordtmp = append(keywordtmp,regexp.QuoteMeta(value))
				}
				keyword:= `(?sim)<\s*title.*>(.*?)`+strings.Join(keywordtmp,".*")+`(.*?)<\s*/\s*title>`
				//keyword := "(?si).*"+strings.Join(fingerprint.Keyword,".*")+".*"
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
					Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,keyword)
				}
			}else {
				keyword:= `(?sim)<\s*title.*>(.*?)`+regexp.QuoteMeta(fingerprint.Keyword[0])+`(.*?)<\s*/\s*title>`
				if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
					Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,keyword)
				}
			}
			//for _,v := range fingerprint.Keyword{
			//	if v!=""{
			//		keyword:= `(?im)<\s*title.*>(.*?)`+v+`(.*?)<\s*/\s*title>`
			//		//keyword := "(?i)<title>"+v+"</title>"
			//		if !util.In(keyword,Fingerprints.Apps[fingerprint.Cms].Text){
			//			Fingerprints.Apps[fingerprint.Cms].Text = append(Fingerprints.Apps[fingerprint.Cms].Text,keyword)
			//		}
			//	}
			//}
		}
	}

	err = SaveJson(Fingerprints)
	if err != nil {
		log.Println(err)
		return
	}
}

func SaveJson(finger wappalyzer.Fingerprints) error {
	var err error
	bf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(bf)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.Encode(finger)
	//fmt.Println(bf.String())
	//// 将结构体编码为JSON格式
	//jsonData, err := json.Marshal(finger)
	//if err != nil {
	//	fmt.Println("JSON encoding error:", err)
	//	return err
	//}
	//// 打印编码后的JSON数据
	//fmt.Println("JSON data:", string(jsonData))

	// 将JSON数据写入文件
	file, err := os.Create("fingerT.json")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return err
	}
	defer file.Close()

	_, err = file.Write(bf.Bytes())
	if err != nil {
		fmt.Println("Error writing JSON data to file:", err)
		return err
	}
	return err
}