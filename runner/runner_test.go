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
