package tracepoint

import manager "github.com/DataDog/ebpf-manager"

var TPEnPrbes = []*manager.Probe{}
var TPEnMaps = []*manager.Map{}

func TPprobeInit() []*manager.Probe {
	TPEnPrbes = append(TPEnPrbes, sirqStructEn.Probes...)
	TPEnPrbes = append(TPEnPrbes, tpStructEn.Probes...)
	return TPEnPrbes
}

func TPmapInit() []*manager.Map {
	TPEnMaps = append(TPEnMaps, sirqStructEn.Maps...)
	TPEnMaps = append(TPEnMaps, tpStructEn.Maps...)
	return TPEnMaps
}
