package httpx

import (
	"log"
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 318, resp.ContentLength)
	})
}
func TestHttp(t *testing.T) {
	ht,err:=New(&DefaultOptions)
	if err != nil {
		log.Println(err)
	}
	req,err:=ht.NewRequest("GET","https://www.baidu.com")
	if err != nil {
		log.Println(err)
	}
	respon,err:=ht.Do(req,UnsafeOptions{})
	log.Println(err)
	log.Println(respon.Raw)
}

