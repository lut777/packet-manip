package main

import (
	"encoding/binary"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var log = logrus.New()

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

var vmInfo1 = VmInfo{
	IfIndex: 3880,
	Ifname:  "ff2834ba93f1_h",
	IfIP:    ip2int(net.ParseIP("192.168.81.170").To4()),
}

var vmInfo2 = VmInfo{
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

var probeIPRcv = manager.Probe{
	ProbeIdentificationPair: manager.ProbeIdentificationPair{
		EBPFFuncName: "ip_rcv_latency",
	},
	SyscallFuncName: "ip_rcv",
}

var probeIPRcvFin = manager.Probe{
	ProbeIdentificationPair: manager.ProbeIdentificationPair{
		EBPFFuncName: "ip_rcv_finish_latency",
	},
	SyscallFuncName: "ip_rcv_finish_core",
}

var map1 = manager.Map{
	Name:       "redirect_map",
	MapOptions: manager.MapOptions{},
}

var map2 = manager.Map{
	Name:       "kernelrx_entry",
	MapOptions: manager.MapOptions{},
}

var m = &manager.Manager{
	Probes: []*manager.Probe{&probe1, &probe2, &probeIPRcv, &probeIPRcvFin},
	Maps:   []*manager.Map{&map1, &map2},
}

var activeBPF1 = "ip_rcv_latency"
var activeBPF2 = "ip_rcv_finish_latency"

var opt = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: activeBPF1,
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: activeBPF2,
					}},
			},
		},
	},
}

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGTERM)

	if err := m.InitWithOptions(recoverAssets(), opt); err != nil {
		log.Fatal(err)
	}

	if err := m.Start(); err != nil {
		log.Fatal(err)
	}
	log.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	redMap, found, err := m.GetMap("redirect_map")
	if err != nil || !found {
		log.Errorf("error :%v, %s", err, "couldn't find shared_cache2 in m1")
	}
	if err = dumpSharedMap(redMap); err != nil {
		log.Errorf("%v", err)
	}

	// updating map KV
	// crud could be found in cilium/ebpf/map.go
	err = redMap.Put(vmInfo1.IfIP, vmInfo1.IfIndex)
	if err != nil {
		log.Errorf("%v", err)
	}
	err = redMap.Put(vmInfo2.IfIP, vmInfo2.IfIndex)
	if err != nil {
		log.Errorf("%v", err)
	}

	// reading

	if err = dumpSharedMap(redMap); err != nil {
		log.Errorf("%v", err)
	}

	defer func() {
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Fatal(err)
		}
	}()

	<-sig
}
