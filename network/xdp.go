package network

import (
	"MyEbpf.io/m/utils"
	"encoding/binary"
	manager "github.com/DataDog/ebpf-manager"
	"log"
	"net"
)

type XDPMapinfo struct {
	key     uint32
	value   uint32
	mapname string
}

type XDPstruct struct {
	utils.Pbstruct
	AddChan chan XDPMapinfo
	DelChan chan XDPMapinfo
}

type VmInfo struct {
	IfIndex uint32
	Ifname  string
	IfIP    uint32
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		panic("no sane way to convert ipv6 into uint32")
	}
	return binary.LittleEndian.Uint32(ip)
}

var VmInfo1 = VmInfo{
	IfIndex: 3880,
	Ifname:  "ff2834ba93f1_h",
	IfIP:    ip2int(net.ParseIP("192.168.81.170").To4()),
}

var VmInfo2 = VmInfo{
	IfIndex: 3882,
	Ifname:  "5f40a314654d_h",
	IfIP:    ip2int(net.ParseIP("192.168.81.212").To4()),
}

var probe1 = manager.Probe{
	ProbeIdentificationPair: manager.ProbeIdentificationPair{
		EBPFFuncName: "ingRedirect",
		EBPFSection:  "xdp",
		UID:          "ff2834ba93f1_h",
	},
	Ifindex:       3880,
	Ifname:        "ff2834ba93f1_h",
	XDPAttachMode: manager.XdpAttachModeSkb,
}

var probe2 = manager.Probe{
	ProbeIdentificationPair: manager.ProbeIdentificationPair{
		UID:          "5f40a314654d_h",
		EBPFFuncName: "ingRedirect",
		EBPFSection:  "xdp",
	},
	Ifindex:       3882,
	Ifname:        "5f40a314654d_h",
	XDPAttachMode: manager.XdpAttachModeSkb,
}

var map1 = manager.Map{
	Name:       "redirect_map",
	MapOptions: manager.MapOptions{},
}

var XdpStructEn = XDPstruct{
	Pbstruct: utils.Pbstruct{
		Probes:   []*manager.Probe{&probe1, &probe2},
		Maps:     []*manager.Map{&map1},
		StopChan: make(chan int),
	},
	AddChan: make(chan XDPMapinfo),
	DelChan: make(chan XDPMapinfo),
}

func (xdp *XDPstruct) Init() {

	go func() {
		for {
			select {
			case input := <-xdp.AddChan:
				redMap, found, err := xdp.Mngr.GetMap(input.mapname)
				if err != nil || !found {
					log.Println("error :%v, %s", err, "couldn't find shared_cache2 in m1")
				}
				// updating map KV
				// crud could be found in cilium/ebpf/map.go
				err = redMap.Put(input.key, input.value)
				if err != nil {
					log.Println("%v", err)
				}

			case input := <-xdp.DelChan:
				redMap, found, err := xdp.Mngr.GetMap(input.mapname)
				if err != nil || !found {
					log.Println("error :%v, %s", err, "couldn't find shared_cache2 in m1")
				}
				err = redMap.Delete(input.key)
				if err != nil {
					log.Println("%v", err)
				}

			case <-xdp.StopChan:
				return
			}
		}
	}()
}

func (xdp *XDPstruct) Stop() {
	xdp.StopChan <- 1
}
