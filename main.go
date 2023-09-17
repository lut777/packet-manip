package main

import (
	"MyEbpf.io/m/network"
	"MyEbpf.io/m/tracepoint"
	"MyEbpf.io/m/utils"
	manager "github.com/DataDog/ebpf-manager"
	"os"
	"os/signal"
	"syscall"
)

var m = &manager.Manager{
	Probes: append(network.XdpStructEn.Probes, tracepoint.TPprobeInit()...),
	Maps:   append(network.XdpStructEn.Maps, tracepoint.TPmapInit()...),
}

// var activeBPF1 = "ip_rcv_latency"
// var activeBPF2 = "ip_rcv_finish_latency"
// var AlleBPFs = []string{"ip_rcv_latency", "ip_rcv_finish_latency"}
var AlleBPFs = []string{"softirq_stat"}

/*var opt = manager.Options{
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
}*/

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGTERM)

	opt := generateOpts()
	utils.Mylog.Printf("options as %v", opt)
	if err := m.InitWithOptions(recoverAssets(), opt); err != nil {
		utils.Mylog.Fatal(err)
	}

	if err := m.Start(); err != nil {
		utils.Mylog.Fatal(err)
	}
	utils.Mylog.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	network.XdpStructEn.Mngr = m
	network.XdpStructEn.Init()

	defer func() {
		network.XdpStructEn.Stop()
		if err := m.Stop(manager.CleanAll); err != nil {
			utils.Mylog.Fatal(err)
		}
	}()

	<-sig
}

func generateOpts() manager.Options {
	var eBPFSelectors []manager.ProbesSelector
	for _, value := range AlleBPFs {
		tmp := manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: value,
		}}
		eBPFSelectors = append(eBPFSelectors, &tmp)
	}
	return manager.Options{
		ActivatedProbes: []manager.ProbesSelector{
			&manager.AllOf{
				Selectors: eBPFSelectors,
			},
		},
	}
}
