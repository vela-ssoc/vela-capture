package capture

import (
	"fmt"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"net"
	"strings"
)

type Interface net.Interface

func (cfg *config) findDev(cnd *cond.Cond) error {
	ift, err := net.Interfaces()
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

func (i Interface) notIP() bool {
	iface := net.Interface(i)
	addr, err := iface.Addrs()
	if err != nil {
		return true
	}

	return len(addr) == 0

}

func (i Interface) matchIP(cnd cond.Method, val string) bool {
	iface := net.Interface(i)
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	if len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		ip := addr.(*net.IPAddr).String()
		if cnd(ip, val) {
			return true
		}
	}
	return false
}

func (i Interface) Compare(key, val string, cnd cond.Method) bool {
	switch key {
	case "name":
		return cnd(i.Name, val)
	case "flag":
		return cnd(i.Flags.String(), val)
	case "loopback":
		return auxlib.ToString(strings.Contains(i.Flags.String(), "loopback")) == val
	case "not_ip":
		return auxlib.ToString(i.notIP()) == val

	case "up":
		return auxlib.ToString(strings.HasPrefix(i.Flags.String(), "up|")) == val
	case "ip":
		return i.matchIP(cnd, val)

	default:
		return false
	}
}
