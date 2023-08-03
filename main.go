package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = -1
	handle       *pcap.Handle
)

type Msg struct {
	Timestamp time.Time
	Src       string
	SrcIP     string
	Dst       string
	DstIP     string
	FIN       bool
	RST       bool
	Seq       uint32
	Ack       uint32
}

func main() {
	Run()
}

func Run() {
	log.Println("version:1.0.0")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	var port string
	var device string
	flag.StringVar(&port, "p", "50055", "服务启动端口")
	flag.StringVar(&device, "d", "eth0", "网卡设备名称")
	flag.Parse()

	MsgThreadQueueSize := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "FIN_Metric",
		Help: "FIN数据包发送次数",
	}, []string{"src", "dst", "status"})
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		MsgThreadQueueSize,
	)

	m := make(map[string]Msg)
	var mu sync.Mutex

	// 定时清理被动发送的FIN包的数据
	go func() {
		for {
			mu.Lock()
			log.Println("清理map", len(m))
			for k, v := range m {
				if v.Timestamp.Add(time.Second * 60).Before(time.Now()) {
					delete(m, k)
				}
			}
			log.Println("清理完毕", len(m))
			mu.Unlock()
			time.Sleep(time.Second * 60)
		}
	}()

	go func() {
		//handle, err = pcap.OpenLive(FindDevice().Name, snapshot_len, promiscuous, timeout)
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		// 过滤出FIN、RST报文且端口不是22
		//var filter string = "host 39.101.203.25 and tcp[tcpflags] & (tcp-fin|tcp-rst) != 0 and port not 22"
		var filter string = "tcp[tcpflags] & (tcp-fin|tcp-rst) != 0 and port not 22 and host not 8.219.88.59"
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}

		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		//for packet := range packetSource.Packets() {
		//	ipLayer := packet.Layer(layers.LayerTypeIPv4)
		//	if ipLayer == nil {
		//		continue
		//	}
		//	ip, _ := ipLayer.(*layers.IPv4)
		//	tcpLayer := packet.Layer(layers.LayerTypeTCP)
		//	if tcpLayer == nil {
		//		continue
		//	}
		//	tcp, _ := tcpLayer.(*layers.TCP)
		//
		//	var data1 = Msg{
		//		Timestamp: packet.Metadata().Timestamp,
		//		Src:       fmt.Sprintf("%v:%v", ip.SrcIP.String(), tcp.SrcPort.String()),
		//		SrcIP:     ip.SrcIP.String(),
		//		Dst:       fmt.Sprintf("%v:%v", ip.DstIP.String(), tcp.DstPort.String()),
		//		DstIP:     ip.DstIP.String(),
		//		FIN:       tcp.FIN,
		//		RST:       tcp.RST,
		//		Seq:       tcp.Seq,
		//		Ack:       tcp.Ack,
		//	}
		//
		//	if data1.RST {
		//		MsgThreadQueueSize.WithLabelValues(data1.SrcIP, data1.DstIP, "RST").Inc()
		//	}
		//	if data1.FIN {
		//		mu.Lock()
		//		m[data1.Src+data1.Dst] = data1
		//
		//		data2, ok := m[data1.Dst+data1.Src]
		//		if ok {
		//			if data1.Seq+1 == data2.Ack {
		//				// data1 is first FIN
		//				MsgThreadQueueSize.WithLabelValues(data1.SrcIP, data1.DstIP, "FIN").Inc()
		//				delete(m, data1.Src+data1.Dst)
		//				delete(m, data1.Dst+data1.Src)
		//				//fmt.Printf("%+v\n", data1)
		//			}
		//			if data2.Seq+1 == data1.Ack {
		//				// data2 is first FIN
		//				MsgThreadQueueSize.WithLabelValues(data2.SrcIP, data2.DstIP, "FIN").Inc()
		//				delete(m, data2.Src+data2.Dst)
		//				delete(m, data2.Dst+data2.Src)
		//				//fmt.Printf("%+v\n", data2)
		//			}
		//		}
		//		mu.Unlock()
		//	}
		//}

		// 复用优化
		var ip layers.IPv4
		var tcp layers.TCP
		var ethLayer layers.Ethernet
		for packet := range packetSource.Packets() {
			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&ethLayer,
				&ip,
				&tcp,
			)
			foundLayerTypes := []gopacket.LayerType{}
			parser.DecodeLayers(packet.Data(), &foundLayerTypes)
			if len(foundLayerTypes) != 3 {
				log.Println("解析错误，len(foundLayerTypes):", len(foundLayerTypes))
				continue
			}

			var data1 = Msg{
				Timestamp: packet.Metadata().Timestamp,
				Src:       fmt.Sprintf("%v:%v", ip.SrcIP.String(), tcp.SrcPort.String()),
				SrcIP:     ip.SrcIP.String(),
				Dst:       fmt.Sprintf("%v:%v", ip.DstIP.String(), tcp.DstPort.String()),
				DstIP:     ip.DstIP.String(),
				FIN:       tcp.FIN,
				RST:       tcp.RST,
				Seq:       tcp.Seq,
				Ack:       tcp.Ack,
			}

			if data1.RST {
				MsgThreadQueueSize.WithLabelValues(data1.SrcIP, data1.DstIP, "RST").Inc()
			}
			if data1.FIN {
				mu.Lock()
				m[data1.Src+data1.Dst] = data1

				data2, ok := m[data1.Dst+data1.Src]
				if ok {
					if data1.Seq+1 == data2.Ack {
						// data1 is first FIN
						MsgThreadQueueSize.WithLabelValues(data1.SrcIP, data1.DstIP, "FIN").Inc()
						delete(m, data1.Src+data1.Dst)
						delete(m, data1.Dst+data1.Src)
					}
					if data2.Seq+1 == data1.Ack {
						// data2 is first FIN
						MsgThreadQueueSize.WithLabelValues(data2.SrcIP, data2.DstIP, "FIN").Inc()
						delete(m, data2.Src+data2.Dst)
						delete(m, data2.Dst+data2.Src)
					}
				}
				mu.Unlock()
			}
		}
	}()

	// Expose /metrics HTTP endpoint using the created custom registry.
	http.Handle(
		"/metrics", promhttp.HandlerFor(
			registry,
			promhttp.HandlerOpts{
				EnableOpenMetrics: true,
			}),
	)
	log.Printf("server start at %v\n", port)
	log.Fatalln(http.ListenAndServe(":"+port, nil))
}

// FindDevice 获取网络设备
func FindDevice() pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == "172.16.25.50" {
				return device
			}
		}
	}
	return pcap.Interface{}
}
