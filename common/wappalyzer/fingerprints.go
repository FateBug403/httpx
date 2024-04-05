package wappalyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Fingerprints 包含一个指纹图谱，用于技术检测
type Fingerprints struct {
	// app按<name, fingerprint>组织
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint 是一种经过验证和标准化的技术的单一信息
type Fingerprint struct {
	Cookies     map[string]string   `json:"cookies"`
	JS          []string            `json:"js"`
	Headers     map[string]string   `json:"headers"`
	HeadersRaw 		[]string			`json:"headers_raw"` // 通过匹配header的raw
	HTML        []string            `json:"html"` // 匹配html片段
	CSS         []string            `json:"css"`
	Script      []string            `json:"scripts"`
	Meta        map[string][]string `json:"meta"`
	Implies     []string            `json:"implies"`
	Description string              `json:"description"`
	Website     string              `json:"website"`
	Text 		[]string			`json:"text"` // 匹配纯文本
	IconHash	[]string 			`json:"icon_hash"`
	Pocs 		[]string			`json:"pocs"`

}

// CompiledFingerprints 包含一个指纹图谱，用于技术检测
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
}

// CompiledFingerprint 包含来自tech json的编译指纹
type CompiledFingerprint struct {
	// Implies包含该技术隐含的技术
	implies []string
	// description 包含指纹描述
	description string
	// website 包含与指纹相关联的URL
	website string
	// cookies 包含目标cookie的指纹
	cookies map[string]*versionRegex
	// js contains fingerprints for the js file
	js []*versionRegex
	// headers 包含目标标头的指纹
	headers map[string]*versionRegex
	// html 包含目标HTML的指纹
	html []*versionRegex
	// script 包含脚本标记的指纹
	script []*versionRegex
	// meta 包含元标签的指纹
	meta map[string][]*versionRegex
	// text 匹配相应body里的纯文本信息
	text []*versionRegex
	// 在header头raw中匹配关键字
	headersRaw []*versionRegex
	// 在header头raw中匹配关键字
	iconHash []*versionRegex
	// 指纹具有的poc名字
	pocs []string
}

// AppInfo 包含应用的基本信息。
type AppInfo struct {
	Description string
	Website     string
}
// 版本正则表达式
type versionRegex struct {
	regex     *regexp.Regexp
	skipRegex bool
	group     int
}

const versionPrefix = "version:\\"

// newVersionRegex 创建一个匹配regex的新版本
// TODO: handles simple group cases only as of now (no ternary)
func newVersionRegex(value string) (*versionRegex, error) {
	splitted := strings.Split(value, "\\;")
	if len(splitted) == 0 {
		return nil, nil
	}

	compiled, err := regexp.Compile(splitted[0])
	if err != nil {
		return nil, err
	}
	skipRegex := splitted[0] == ""
	regex := &versionRegex{regex: compiled, skipRegex: skipRegex}
	for _, part := range splitted {
		if strings.HasPrefix(part, versionPrefix) {
			group := strings.TrimPrefix(part, versionPrefix)
			if parsed, err := strconv.Atoi(group); err == nil {
				regex.group = parsed
			}
		}
	}
	return regex, nil
}

// MatchString 如果匹配一个版本正则表达式，则返回true。
// 如果有，也会返回找到的版本。
func (v *versionRegex) MatchString(value string) (bool, string) {
	if v.skipRegex {
		return true, ""
	}
	//log.Println(v.regex.String())
	matches := v.regex.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return false, ""
	}

	var version string
	if v.group > 0 {
		for _, match := range matches {
			version = match[v.group]
		}
	}
	return true, version
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
	textPart
	headerRawPart
	iconHashPart
)

// compileFingerprint loadPatterns加载指纹模式并编译正则表达式
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		cookies:     make(map[string]*versionRegex),
		js:          make([]*versionRegex, 0, len(fingerprint.JS)),
		headers:     make(map[string]*versionRegex),
		html:        make([]*versionRegex, 0, len(fingerprint.HTML)),
		script:      make([]*versionRegex, 0, len(fingerprint.Script)),
		meta:        make(map[string][]*versionRegex),
		text:		 make([]*versionRegex, 0, len(fingerprint.Text)),
		headersRaw: make([]*versionRegex, 0, len(fingerprint.HeadersRaw)),
		pocs: fingerprint.Pocs,
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for _, pattern := range fingerprint.JS {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.js = append(compiled.js, fingerprint)
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Text {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.text = append(compiled.text, fingerprint)
	}

	for _, pattern := range fingerprint.HeadersRaw {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.headersRaw = append(compiled.headersRaw, fingerprint)
	}

	for _, pattern := range fingerprint.IconHash {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.iconHash = append(compiled.iconHash, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*versionRegex

		for _, pattern := range patterns {
			fingerprint, err := newVersionRegex(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

// matchString 匹配指纹的字符串
func (f *CompiledFingerprints) matchString(data string, part part) []string {
	var matched bool
	var technologies []string
	for app, fingerprint := range f.Apps {
		var version string
		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.script {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case textPart:
			//num := 0
			for _, pattern := range fingerprint.text {
				if valid, versionString := pattern.MatchString(data); valid {
					//num=num+1
					matched = true
					version = versionString
				}
			}
			//if num!=len(fingerprint.text){ // 判断是不是每个规则都匹配
			//	matched = false
			//}
		case headerRawPart:
			//num := 0
			for _, pattern := range fingerprint.headersRaw {
				if valid, versionString := pattern.MatchString(data); valid {
					//num=num+1
					matched = true
					version = versionString
				}
			}
			//if num!=len(fingerprint.headersRaw){
			//	matched = false
			//}
		case iconHashPart:
			//num := 0
			for _, pattern := range fingerprint.iconHash {
				if valid, versionString := pattern.MatchString(data); valid {
					//num=num+1
					matched = true
					version = versionString
				}
			}
			//if num!=len(fingerprint.iconHash){
			//	matched = false
			//}
		}

		// 如果没有匹配，继续下一个指纹
		if !matched {
			continue
		}

		if version != "" {
			app = formatAppVersion(app, version)
		}
		// 附加技术以及隐含的技术
		if len(fingerprint.pocs)>0{
			technologies = append(technologies, app+"{"+strings.Join(fingerprint.pocs,",")+"}")
			//technologies = append(technologies, fingerprint.pocs...)
		}else {
			technologies = append(technologies, app)
		}
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		var version string
		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		if version != "" {
			app = formatAppVersion(app, version)
		}
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		var version string

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
				}
				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		if version != "" {
			app = formatAppVersion(app, version)
		}
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

func formatAppVersion(app, version string) string {
	return fmt.Sprintf("%s:%s", app, version)
}
