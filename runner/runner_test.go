package runner

import (
	"bufio"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
	"log"
	"os"
	"strconv"
	"testing"
)

func TestRequest(t *testing.T){
	options := &Options{}
	options.ExtractTitle=true
	httpxRunner, err := New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	//httpxRunner.RunEnumeration2("www.baidu.com",func(r Result) {
	//	//log.Println(r.URL)
	//})
	links := ReadFile("test.txt")
	wg := sizedwaitgroup.New(50)
	for _,value:=range links{
		wg.Add()
		go func() {
			defer wg.Done()
			httpxRunner.RunAlone(value,func(r Result) {
				log.Println(r.URL+"--->"+r.Title+"--->"+ strconv.Itoa(r.StatusCode))
			})
		}()
	}
	wg.Wait()
	httpxRunner.Close()
}
func ReadFile(path string) []string{
	file,err := os.Open(path)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	// 创建一个 bufio.Reader 来包装文件读取器
	reader := bufio.NewReader(file)
	var lines []string
	// 逐行读取文件内容
	for {
		line, isPrefix, err := reader.ReadLine()
		if err != nil {
			// 如果遇到错误，可能是文件结束
			break
		}
		// 如果 isPrefix 为 true，表示当前行太长，需要继续读取下一行来组成完整的行
		if isPrefix {
			//fmt.Println("当前行太长，需要继续读取下一行")
			continue
		}

		lines = append(lines, string(line))
	}
	return lines
}

func TestHttpx(t *testing.T) {
	option := DefaultOptions
	//option.NoDecode =true
	//option.HTTPProxy = "socks5://127.0.0.1:7890"
	//ports :="21,22,23,25,53,80,81,82,83,85,88,110,111,135,139,143,161,443,444,465,500,554,587,888,993,995,1024,1025,1026,1027,1080,1194,1234,1433,1701,1723,1900,2000,2080,2082,2083,2086,2087,2096,2121,2222,3000,3128,3306,3389,4443,4444,4567,5000,5001,5357,5555,5683,5985,7000,7547,7777,8000,8001,8008,8009,8010,8020,8080,8081,8082,8086,8088,8089,8090,8099,8291,8443,8800,8880,8888,8889,9000,9001,9003,9010,9080,9090,9100,9200,9443,9527,9530,9999,10000,10001,12345,20000,49152,52869"
	//ports := "9999"
	//err := option.CustomPorts.Set(ports)
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
	//option.InputTargetHost = []string{
	//	"202.203.179.107",
	//}
	hpx, err := New(option)
	if err != nil {
		log.Println(err)
	}
	hpx.RunAlone("cip.cc", func(r Result) {
		//log.Println(r)
		log.Println(r.ResponseDateStr)
	})
}
