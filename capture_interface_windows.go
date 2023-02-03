package capture

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"net"
)

type Interface pcap.Interface

func (i Interface) notIP() bool {
	if len(i.Addresses) == 0 {
		return true
	}

	return false
}

func (i Interface) isLoopBack() bool {
	if len(i.Addresses) == 0 {
		return false
	}

	for _, dev := range i.Addresses {
		if dev.IP.IsLoopback() {
			return true
		}
	}

	return false
}

func (cfg *config) findDev(cnd *cond.Cond) error {

	ift, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	if len(ift) == 0 {
		return fmt.Errorf("not found live inteface")
	}

	for _, item := range ift {
		dev := Interface(item)
		if cnd.Match(dev) {
			cfg.devs = append(cfg.devs, dev)
		}
	}

	if len(cfg.devs) == 0 {
		return fmt.Errorf("not live interface")
	}

	return nil
}

func (i Interface) matchIP(cnd cond.Method, val string) bool {
	if len(i.Addresses) == 0 {
		return false
	}
	for _, addr := range i.Addresses {
		ip := addr.IP.String()
		if cnd(ip, val) {
			return true
		}
	}
	return false
}

func (i Interface) Compare(key, val string, cnd cond.Method) bool {
	flags := net.Flags(i.Flags)
	switch key {
	case "name":
		return cnd(i.Name, val)
	case "flag":
		return cnd(flags.String(), val)
	case "loopback":
		return auxlib.ToString(i.isLoopBack()) == val
	case "not_ip":
		return auxlib.ToString(i.notIP()) == val
	case "up":
		return val == "true"
	case "ip":
		return i.matchIP(cnd, val)
	default:
		return false
	}
}
