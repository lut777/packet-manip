package tracepoint

import (
	"MyEbpf.io/m/utils"
	manager "github.com/DataDog/ebpf-manager"
)

type SirqMapinfo struct {
	key     uint32
	value   uint32
	mapname string
}

type Sirqstruct struct {
	utils.Pbstruct
}

var probeISirq = manager.Probe{
	ProbeIdentificationPair: manager.ProbeIdentificationPair{
		EBPFFuncName: "softirq_stat",
	},
	SyscallFuncName: "softirq_entry",
}

var mapSirq = manager.Map{
	Name:       "kernelrx_entry",
	MapOptions: manager.MapOptions{},
}

var sirqStructEn = Sirqstruct{
	Pbstruct: utils.Pbstruct{
		Probes:   []*manager.Probe{&probeISirq},
		Maps:     []*manager.Map{&mapSirq},
		StopChan: make(chan int),
	},
}
