package main

import (
	"flag"
	"fmt"
	"gitee.com/ttmasx/cob/proxy"
)

func main() {
	var port int
	flag.IntVar(&port, "p", 2023, "端口")
	flag.Parse()
	proxy.DProxy.CreateFileServerByGin("/file", "", fmt.Sprintf("%v", port), false)
}
