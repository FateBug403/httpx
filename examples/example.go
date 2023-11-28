package main

import (
	"log"

	"github.com/FateBug403/httpx/runner"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice{"https://www.sto.cn", "https://wap.sto.cn:80", "localhost"},
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration(func(r runner.Result) {
		log.Println(r.Host)
	})
}
