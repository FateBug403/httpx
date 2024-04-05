package wappalyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	fingerprintModel "github.com/FateBug403/httpx/common/wappalyzer/model/fingerprint"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"strings"
)

// Wappalyze 是一个用于技术检测的客户端
type Wappalyze struct {
	fingerprints *CompiledFingerprints
}

// New 创建一个新的技术检测实例
func New() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	err := wappalyze.loadFingerprintsFormJSON()
	if err != nil {
		return nil, err
	}

	return wappalyze, nil
}


// ImportFingerprintsForDatabase 从数据库中导入指纹
func (s *Wappalyze) ImportFingerprintsForDatabase(dsn string) error {
	log.Println("导入指纹")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		return err
	}
	var tmpfingerprint []fingerprintModel.Fingerprint
	db.Find(tmpfingerprint)
	for _, fingerprint := range tmpfingerprint {
		// 赋值
		var fingerprintstmp Fingerprint
		fingerprintstmp.JS = fingerprint.JS
		fingerprintstmp.Meta=fingerprint.Meta
		fingerprintstmp.Website = fingerprint.Website
		fingerprintstmp.CSS = fingerprint.CSS
		fingerprintstmp.HTML = fingerprint.HTML
		fingerprintstmp.Script = fingerprint.Script
		fingerprintstmp.Headers=fingerprint.Headers
		fingerprintstmp.Cookies =fingerprint.Cookies
		fingerprintstmp.Implies =fingerprint.Implies
		fingerprintstmp.Description =fingerprint.Description

		// 保存到数据库
		//s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
	}
	return nil
}

func (s *Wappalyze) loadFingerprintsFormJSON() error {
	var err error
	var MyFingerprints Fingerprints

	err = json.Unmarshal([]byte(finger), &MyFingerprints) // 将指定json文件反序列化到指纹结构体中
	if err != nil {
		return err
	}
	for name, MyFingerprint := range MyFingerprints.Apps {
		s.fingerprints.Apps[name] = compileFingerprint(MyFingerprint)
	}
	return err
}

// Fingerprint  基于接收到的响应头和响应体，识别目标的技术，
//在调用这个函数时不应该改变函数体，否则可能会导致意想不到的事情。
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte,faviconHash string) map[string]struct{} {
	uniqueFingerprints := newUniqueFingerprints()

	// 小写的所有我们收到的检查
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)
	// 检查图标指纹
	if faviconHash!=""{
		//log.Println("图标探测")
		for _, application := range s.checkFaviconHash(faviconHash) {
			uniqueFingerprints.setIfNotExists(application)
		}
	}

	// 如果头检查的次数大于0，则运行基于头的指纹识别.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.setIfNotExists(application)
	}

	// 从cookie中寻找指纹
	cookies := s.findSetCookie(normalizedHeaders)
	// 如果我们有一个set-cookie报头，运行基于cookie的指纹识别
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.setIfNotExists(application)
		}
	}

	// 最后检查一下body里的东西
	bodyTech := s.checkBody(normalizedBody)
	for _, application := range bodyTech {
		uniqueFingerprints.setIfNotExists(application)
	}
	return uniqueFingerprints.getValues()
}

type uniqueFingerprints struct {
	values map[string]struct{}
}

func newUniqueFingerprints() uniqueFingerprints {
	return uniqueFingerprints{
		values: make(map[string]struct{}),
	}
}

func (u uniqueFingerprints) getValues() map[string]struct{} {
	return u.values
}

const versionSeparator = ":"

// separateAppVersion returns app name and version
func separateAppVersion(value string) (string, string) {
	if strings.Contains(value, versionSeparator) {
		if parts := strings.Split(value, versionSeparator); len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return value, ""
}

func (u uniqueFingerprints) setIfNotExists(value string) {
	app, version := separateAppVersion(value)
	if _, ok := u.values[app]; ok {
		// Handles case when we get additional version information next
		if version != "" {
			delete(u.values, app)
			u.values[strings.Join([]string{app, version}, versionSeparator)] = struct{}{}
		}
		return
	}

	// Handle duplication for : based values
	for k := range u.values {
		if strings.Contains(k, versionSeparator) {
			if parts := strings.Split(k, versionSeparator); len(parts) == 2 && parts[0] == value {
				return
			}
		}
	}
	u.values[value] = struct{}{}
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	uniqueFingerprints := newUniqueFingerprints()

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.setIfNotExists(application)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.setIfNotExists(application)
		}
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		for _, application := range bodyTech {
			uniqueFingerprints.setIfNotExists(application)
		}
		title := s.getTitle(body)
		return uniqueFingerprints.getValues(), title
	}
	return uniqueFingerprints.getValues(), ""
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
//func (s *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
//	apps := s.Fingerprint(headers, body)
//	result := make(map[string]AppInfo, len(apps))
//
//	for app := range apps {
//		if fingerprint, ok := s.fingerprints.Apps[app]; ok {
//			result[app] = AppInfo{
//				Description: fingerprint.description,
//				Website:     fingerprint.website,
//			}
//		}
//	}
//
//	return result
//}
