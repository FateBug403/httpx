package runner

import (
	"log"
	"testing"
	"time"
)

func TestHeadless(t *testing.T) {
	browser, err := NewBrowser("", false)
	if err != nil {
		log.Println(err)
	}
	screenshotBytes, headlessBody, err := browser.ScreenshotWithBody("http://lzuedf.lzu.edu.cn", 15*time.Second)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(string(screenshotBytes))
	log.Println(headlessBody)
}