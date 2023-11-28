package httpx

import (
	"net/http"
	"strings"
	"time"
)

// Options contains configuration options for the client
type Options struct {
	RandomAgent      bool
	DefaultUserAgent string
	HTTPProxy        string
	SocksProxy       string
	Threads          int
	CdnCheck         bool
	ExcludeCdn       bool
	// Timeout 等待请求的最长时间是多少
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax      int
	CustomHeaders map[string]string
	// VHostSimilarityRatio 1 - 100
	VHostSimilarityRatio int
	FollowRedirects      bool
	FollowHostRedirects  bool
	MaxRedirects         int
	Unsafe               bool
	TLSGrab              bool
	ZTLS                 bool
	// VHOSTs options
	VHostIgnoreStatusCode     bool
	VHostIgnoreContentLength  bool
	VHostIgnoreNumberOfWords  bool
	VHostIgnoreNumberOfLines  bool
	VHostStripHTML            bool
	Allow                     []string
	Deny                      []string
	MaxResponseBodySizeToSave int64
	MaxResponseBodySizeToRead int64
	UnsafeURI                 string
	Resolvers                 []string
	customCookies             []*http.Cookie
	SniName                   string
}

// DefaultOptions contains the default options
var DefaultOptions = Options{
	RandomAgent:  true,
	Threads:      25,
	Timeout:      15 * time.Second,
	RetryMax:     3,
	MaxRedirects: 10,
	Unsafe:       false,
	CdnCheck:     true,
	ExcludeCdn:   false,
	//MaxResponseBodySizeToRead: 102400,
	// VHOSTs options
	VHostIgnoreStatusCode:    false,
	VHostIgnoreContentLength: true,
	VHostIgnoreNumberOfWords: false,
	VHostIgnoreNumberOfLines: false,
	VHostStripHTML:           false,
	VHostSimilarityRatio:     85,
	DefaultUserAgent:         "httpx - Open-source project (github.com/FateBug403/httpx)",
}

func (options *Options) parseCustomCookies() {
	// parse and fill the custom field
	for k, v := range options.CustomHeaders {
		if strings.EqualFold(k, "cookie") {
			req := http.Request{Header: http.Header{"Cookie": []string{v}}}
			options.customCookies = req.Cookies()
		}
	}
}

func (options *Options) hasCustomCookies() bool {
	return len(options.customCookies) > 0
}
