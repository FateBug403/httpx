package wappalyzer

import (
	_ "embed"
)

//go:embed fingerprints_data.json
var fingerprints string

//go:embed finger.json
var finger string

//go:embed fingerChonsou.json
var fingerChonsou string

//go:embed FateBugFingerprint.json
var fateBugFingerprint string