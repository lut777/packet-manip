package main

import (
	"MyEbpf.io/m/network"
	"MyEbpf.io/m/tracepoint"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

var log = logrus.New()

var m = &manager.Manager{
	Probes: append(network.XdpStructEn.Probes, tracepoint.TPStructEn.Probes...),
	Maps:   append(network.XdpStructEn.Maps, tracepoint.TPStructEn.Maps...),
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

	network.XdpStructEn.Mngr = m
	network.XdpStructEn.Init()

	defer func() {
		network.XdpStructEn.Stop()
		if err := m.Stop(manager.CleanAll); err != nil {
			log.Fatal(err)
		}
	}()

	<-sig
}
