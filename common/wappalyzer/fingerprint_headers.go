package wappalyzer

import (
	"fmt"
	"strings"
)

// checkHeaders checks if the headers for a target match the fingerprints
// and returns the matched IDs if any.
func (s *Wappalyze) checkHeaders(headers map[string]string) []string {
	var technologies []string
	// 将header头转化为字符串
	headerString := ""
	for key, value := range headers {
		headerString += fmt.Sprintf("%s: %s\n", key, value)
	}
	technologies = append(technologies,s.fingerprints.matchString(headerString,headerRawPart)...)
	technologies = append(technologies,s.fingerprints.matchMapString(headers, headersPart)...)
	return technologies
}

func (s *Wappalyze) checkFaviconHash(faviconHash string) []string {
	technologies:=s.fingerprints.matchString(faviconHash,iconHashPart)
	return technologies
}

// normalizeHeaders normalizes the headers for the tech discovery on headers
func (s *Wappalyze) normalizeHeaders(headers map[string][]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	data := getHeadersMap(headers)

	for header, value := range data {
		normalized[strings.ToLower(header)] = strings.ToLower(value)
	}
	return normalized
}

// GetHeadersMap returns a map[string]string of response headers
func getHeadersMap(headersArray map[string][]string) map[string]string {
	headers := make(map[string]string, len(headersArray))

	builder := &strings.Builder{}
	for key, value := range headersArray {
		for i, v := range value {
			builder.WriteString(v)
			if i != len(value)-1 {
				builder.WriteString(", ")
			}
		}
		headerValue := builder.String()

		headers[key] = headerValue
		builder.Reset()
	}
	return headers
}
