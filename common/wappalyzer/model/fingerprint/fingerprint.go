package fingerprint

import (
	"database/sql/driver"
	"encoding/json"
)

// Fingerprint 是一种经过验证和标准化的技术的单一信息
type Fingerprint struct {
	Name        string    `json:"name" gorm:"column:name"`
	Cookies     Cookies   `json:"cookies" gorm:"type:json;column:cookies;"`
	JS          JSs       `json:"js" gorm:"type:json;column:js;"`
	Headers     Headers   `json:"headers" gorm:"type:json;column:headers;"`
	HTML        Html      `json:"html" gorm:"type:json;column:html;"`
	CSS         CSS       `json:"css" gorm:"type:json;column:css;"`
	Script      Script    `json:"script" gorm:"type:json;column:script;"`
	Meta        Meta      `json:"meta" gorm:"type:json;column:meta;"`
	Implies     Implies   `json:"implies" gorm:"type:json;column:implies;"`
	Description string    `json:"description"`
	Website     string    `json:"website"`
	Text        Text      `json:"text" gorm:"type:json;column:text;"`
	HeaderRaw   HeaderRaw `json:"headerRaw" gorm:"type:json;column:headerRaw;"`
	IconHash    IconHash  `json:"iconHash" gorm:"type:json;column:iconHash;"`
	POCS        POCS      `json:"pocs" gorm:"type:json;column:pocs;"`
}

// Cookies 保存cookie指纹信息的字典
type Cookies map[string]string
func (c Cookies) Value() (driver.Value, error) {
	return json.Marshal(c)
}
func (c *Cookies) Scan(value interface{}) error {
	if val, ok := value.([]byte); ok {
		r := json.Unmarshal(val, c)
		return r
	}
	return nil
}

// Headers 保存cookie指纹信息的字典
type Headers map[string]string
func (h Headers) Value() (driver.Value, error) {
	return json.Marshal(h)
}
func (h *Headers) Scan(value interface{}) error {
	if val, ok := value.([]byte); ok {
		r := json.Unmarshal(val, h)
		return r
	}
	return nil
}

// Meta 保存cookie指纹信息的字典
type Meta map[string][]string
func (m Meta) Value() (driver.Value, error) {
	return json.Marshal(m)
}
func (m *Meta) Scan(value interface{}) error {
	if val, ok := value.([]byte); ok {
		r := json.Unmarshal(val, m)
		return r
	}
	return nil
}

// JSs 保存JS指纹信息的切片
type JSs []string
func (j JSs) Value() (driver.Value, error) {
	b, err := json.Marshal(j)
	return string(b), err
}
func (j *JSs) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, j)
		return r
	}
	return nil
}

// Html 保存HTML中指纹信息的切片
type Html []string
func (h Html) Value() (driver.Value, error) {
	b, err := json.Marshal(h)
	return string(b), err
}
func (h *Html) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, h)
		return r
	}
	return nil
}

// Text 保存HTML中指纹信息的切片
type Text []string
func (t Text) Value() (driver.Value, error) {
	b, err := json.Marshal(t)
	return string(b), err
}
func (t *Text) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, t)
		return r
	}
	return nil
}

// HeaderRaw 保存HTML中指纹信息的切片
type HeaderRaw []string
func (h HeaderRaw) Value() (driver.Value, error) {
	b, err := json.Marshal(h)
	return string(b), err
}
func (h *HeaderRaw) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, h)
		return r
	}
	return nil
}

// CSS 保存JS指纹信息的切片
type CSS []string
func (c CSS) Value() (driver.Value, error) {
	b, err := json.Marshal(c)
	return string(b), err
}
func (c *CSS) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, c)
		return r
	}
	return nil
}

// Script 保存JS指纹信息的切片
type Script []string
func (s Script) Value() (driver.Value, error) {
	b, err := json.Marshal(s)
	return string(b), err
}
func (s *Script) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, s)
		return r
	}
	return nil
}

// Implies 保存JS指纹信息的切片
type Implies []string
func (i Implies) Value() (driver.Value, error) {
	b, err := json.Marshal(i)
	return string(b), err
}
func (i *Implies) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, i)
		return r
	}
	return nil
}

// IconHash 保存图标指纹信息
type IconHash []string
func (i IconHash) Value() (driver.Value, error) {
	b, err := json.Marshal(i)
	return string(b), err
}
func (i *IconHash) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, i)
		return r
	}
	return nil
}

// POCS 指纹POC信息
type POCS []string
func (p POCS) Value() (driver.Value, error) {
	b, err := json.Marshal(p)
	return string(b), err
}
func (p *POCS) Scan(input interface{}) error {
	if val, ok := input.([]byte); ok {
		r := json.Unmarshal(val, p)
		return r
	}
	return nil
}

// TableName TasksInfoscan 表名
func (Fingerprint) TableName() string {
	return "fingerprint"
}