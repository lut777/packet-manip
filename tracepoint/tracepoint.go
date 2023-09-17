package tracepoint

import (
	"MyEbpf.io/m/utils"
	manager "github.com/DataDog/ebpf-manager"
)

type TPMapinfo struct {
	key     uint32
	value   uint32
	mapname string
}

type TPstruct struct {
	utils.Pbstruct
	AddChan chan TPMapinfo
	DelChan chan TPMapinfo
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

var map2 = manager.Map{
	Name:       "kernelrx_entry",
	MapOptions: manager.MapOptions{},
}

var tpStructEn = TPstruct{
	Pbstruct: utils.Pbstruct{
		Probes:   []*manager.Probe{&probeIPRcv, &probeIPRcvFin},
		Maps:     []*manager.Map{&map2},
		StopChan: make(chan int),
	},
	AddChan: make(chan TPMapinfo),
	DelChan: make(chan TPMapinfo),
}
