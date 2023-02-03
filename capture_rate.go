package capture

import (
	"bytes"
	"fmt"
	"github.com/vela-ssoc/vela-kit/vela"
	"strconv"
	"strings"
)

func RateByDstIP(box *Box) string {
	return box.cnn.DstIP.String()
}

func RateByDst(box *Box) string {
	return box.cnn.DstIP.String() + ":" + strconv.Itoa(int(box.cnn.DstPort))
}

func RateByDstPort(box *Box) string {
	return strconv.Itoa(int(box.cnn.DstPort))
}

func RateBySrcIP(box *Box) string {
	return strconv.Itoa(int(box.cnn.DstPort))
}

func RateBySrc(box *Box) string {
	return box.cnn.SrcIP.String() + ":" + strconv.Itoa(int(box.cnn.SrcPort))
}
func RateBySrcPort(box *Box) string {
	return strconv.Itoa(int(box.cnn.SrcPort))
}

type RateConfig struct {
	param  string      //参数
	ttl    int         //时间
	shared vela.Shared //对象池
	Index  func(*Box) string
}

func (rc *RateConfig) Prepare() error {
	switch rc.param {
	case "dst":
		rc.Index = RateByDst
	case "dst_ip":
		rc.Index = RateByDstIP
	case "dst_port":
		rc.Index = RateByDstPort
	case "src":
		rc.Index = RateBySrc
	case "src_ip":
		rc.Index = RateBySrcIP
	case "src_port":
		rc.Index = RateBySrcPort

	default:
		tuple := strings.Split(rc.param, ",")
		if len(tuple) == 0 {
			return fmt.Errorf("not found valid rate param")
		}

		rc.Index = func(box *Box) string {
			var buf bytes.Buffer
			for i, key := range tuple {
				if i > 0 {
					buf.WriteByte('_')
				}
				buf.WriteString(box.Index(nil, key).String())
			}
			return buf.String()
		}
	}

	return nil
}
