package capture

import (
	"github.com/google/gopacket/layers"
	"github.com/vela-ssoc/vela-kit/inode"
	ss "github.com/vela-ssoc/vela-ss"
	"strconv"
)

func (c *capture) ref(box *Box) {
	if !c.cfg.ref {
		return
	}

	if len(box.cnn.Proto) < 3 {
		return
	}

	var of *ss.OptionFlag

	switch box.cnn.Proto[:3] {
	case "DNS":
		of, _ = ss.NewOptionFlag("-u")
	case "TCP":
		of, _ = ss.NewOptionFlag("-t")
	case "UDP":
		of, _ = ss.NewOptionFlag("-u")
	default:
		return
	}

	s := ss.By(ss.Flag(of), ss.Cnd(box.ref()), ss.Inode(inode.All()))
	if s == nil || len(s.Sockets) == 0 {
		return
	}
	sock := s.Sockets[0]

	box.cnn.Pid = sock.Pid
	box.cnn.Path = sock.Path
	box.cnn.State = sock.State
	box.cnn.Process = sock.Process
	box.cnn.UID = sock.UID
	box.cnn.IFace = sock.IFace
	box.cnn.Inode = sock.Inode
	box.cnn.Username = sock.Username
}

func (c *capture) L4(box *Box) {
	if c.cfg.proto&(TCP|UDP) == 0 {
		return
	}

	if box.layer < NETWORK {
		return
	}

	tran := box.pkt.TransportLayer()
	if tran == nil {
		return
	}

	switch tran.LayerType() {
	case layers.LayerTypeTCP:

		box.cnn.Proto = "TCP"
		l4 := tran.(*layers.TCP)
		box.cnn.SrcPort = uint16(l4.SrcPort)
		box.cnn.DstPort = uint16(l4.DstPort)

		if l4.SYN {
			box.cnn.Proto = box.cnn.Proto + "|SYN"
		}

		if l4.ACK {
			box.cnn.Proto = box.cnn.Proto + "|ACK"
		}

		if l4.FIN {
			box.cnn.Proto = box.cnn.Proto + "|FIN"
		}

		if l4.RST {
			box.cnn.Proto = box.cnn.Proto + "|RST"
		}

		box.Payload = strconv.Itoa(int(l4.Seq))

	case layers.LayerTypeUDP:
		l4 := tran.(*layers.UDP)
		box.cnn.SrcPort = uint16(l4.SrcPort)
		box.cnn.DstPort = uint16(l4.DstPort)
		box.cnn.Proto = "UDP"
		box.Payload = string(l4.Payload)

	default:
		return
	}

	box.layer = TRANSPORT
}
