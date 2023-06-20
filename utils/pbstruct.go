package utils

import (
	"encoding/binary"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"net"
)

type Pbstruct struct {
	Probes   []*manager.Probe
	Maps     []*manager.Map
	Mngr     *manager.Manager
	StopChan chan int
}

// dumpSharedMap - Dumps the content of the provided map at the provided key
func DumpSharedMap(sharedMap *ebpf.Map) error {
	var key, val uint32
	entries := sharedMap.Iterate()
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		var ip []byte = make([]byte, 4)
		binary.LittleEndian.PutUint32(ip, key)
		IP := net.IPv4(ip[0], ip[1], ip[2], ip[3])
		logrus.Printf("%v contains %v at key %v", sharedMap, val, IP.String())
	}
	return entries.Err()
}
