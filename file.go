package main

import "gitee.com/ttmasx/cob/proxy"

func main() {
	proxy.DProxy.CreateFileServerByGin("/file", "", "2023", false)
}
