package capture

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	ss "github.com/vela-ssoc/vela-ss"
	"net"
)

func addressNotLoopback(sep string) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	offset := 0
	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip.IP.IsLoopback() {
			continue
		}

		if offset > 0 {
			buf.WriteString(sep)
			buf.WriteString(ip.IP.String())
			continue
		}
		buf.WriteString(ip.IP.String())
	}

	return buf.String()
}

func TcpOutboundBPF() string {
	return fmt.Sprintf("tcp and tcp[tcpflags] == tcp-syn and src host %s and host not %s", addressNotLoopback(" or "), xEnv.Broker())
}

func UdpOutboundBPF() string {
	return fmt.Sprintf("udp and src host %s", addressNotLoopback(" or "))
}

func NotListenPort(proto string) lua.Slice {
	var of *ss.OptionFlag
	if proto == "tcp" {
		of, _ = ss.NewOptionFlag("-l -t") //LISTEN TCP IPv4 or IPv6
	} else {
		of, _ = ss.NewOptionFlag("-l -u") //LISTEN UDP IPv4 or IPv6
	}

	ln := ss.By(ss.Flag(of)) // or not(host 192.168.1.1 and dst port 8080)

	if ln == nil || len(ln.Sockets) == 0 {
		return nil
	}

	f := func(sock *ss.Socket) string {
		return fmt.Sprintf("%d", sock.LocalPort)
	}

	var s lua.Slice
	k := 1
	distinct := make(map[string]bool, ln.Total)
	for i := 0; i < ln.Total; i++ {
		v := f(ln.Sockets[i])
		if _, ok := distinct[v]; ok {
			continue
		}
		distinct[v] = true
		s.Set(k, lua.S2L(v))
		k++
	}
	return s
}

func NotListenBPF(proto string) lua.Slice {
	var of *ss.OptionFlag
	if proto == "tcp" {
		of, _ = ss.NewOptionFlag("-l -t")
	} else {
		of, _ = ss.NewOptionFlag("-l -u")
	}

	ln := ss.By(ss.Flag(of)) // or not(host 192.168.1.1 and dst port 8080)
	if ln == nil || len(ln.Sockets) == 0 {
		return nil
	}

	f := func(sock *ss.Socket) string {
		return fmt.Sprintf("(host %s and dst port %d)", sock.LocalIP, sock.LocalPort)
	}

	var s lua.Slice
	k := 1
	distinct := make(map[string]bool, ln.Total)
	for i := 0; i < ln.Total; i++ {
		v := f(ln.Sockets[i])
		if _, ok := distinct[v]; ok {
			continue
		}
		distinct[v] = true
		s.Set(k, lua.S2L(v))
		k++
	}
	return s
}

func RR2Value(r layers.DNSResourceRecord) string {
	switch r.Type {
	case layers.DNSTypeA:
		return r.IP.String()
	case layers.DNSTypeAAAA:
		return r.IP.String()
	case layers.DNSTypeCNAME:
		return auxlib.B2S(r.CNAME)
	default:
		return r.String()
	}
}

func ToReply(rrs []layers.DNSResourceRecord) (ret []RR) {
	n := len(rrs)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		rr := rrs[i]
		ret = append(ret, RR{
			RName:  auxlib.B2S(rr.Name),
			RType:  rr.Type.String(),
			TTL:    rr.TTL,
			RValue: RR2Value(rr),
		})
	}
	return
}
