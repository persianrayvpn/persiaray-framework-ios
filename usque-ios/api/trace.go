package api

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// tunnelTrace counts IP packets crossing the CONNECT-IP pumps. TCP control
// flags are counted separately so a stalled handshake shows up as SYNs with
// no matching SYN-ACKs.
type tunnelTrace struct {
	upPkts, upBytes, upErrs    atomic.Int64
	downPkts, downBytes        atomic.Int64
	upSyn, downSynAck, downRst atomic.Int64
	upRst, upFin, downFin      atomic.Int64
	upDNS, downDNS, upSyn6     atomic.Int64
	upMax, downMax             atomic.Int64
}

const (
	tcpFlagFin = 0x01
	tcpFlagSyn = 0x02
	tcpFlagRst = 0x04
	tcpFlagAck = 0x10
)

// udpPorts returns the source and destination ports of a UDP packet, or ok=false.
func udpPorts(pkt []byte) (src, dst int, ok bool) {
	if len(pkt) < 1 {
		return 0, 0, false
	}
	var off int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != 17 {
			return 0, 0, false
		}
		off = int(pkt[0]&0x0f) * 4
	case 6:
		if len(pkt) < 40 || pkt[6] != 17 {
			return 0, 0, false
		}
		off = 40
	default:
		return 0, 0, false
	}
	if len(pkt) < off+4 {
		return 0, 0, false
	}
	return int(pkt[off])<<8 | int(pkt[off+1]), int(pkt[off+2])<<8 | int(pkt[off+3]), true
}

// tcpFlags returns the TCP flags byte of an IPv4/IPv6 packet, or -1 if the
// packet is not TCP or is too short.
func tcpFlags(pkt []byte) int {
	if len(pkt) < 1 {
		return -1
	}
	var off int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != 6 {
			return -1
		}
		off = int(pkt[0]&0x0f) * 4
	case 6:
		if len(pkt) < 40 || pkt[6] != 6 {
			return -1
		}
		off = 40
	default:
		return -1
	}
	if len(pkt) < off+14 {
		return -1
	}
	return int(pkt[off+13])
}

func storeMax(m *atomic.Int64, v int64) {
	for {
		cur := m.Load()
		if v <= cur || m.CompareAndSwap(cur, v) {
			return
		}
	}
}

func (t *tunnelTrace) up(pkt []byte) {
	t.upPkts.Add(1)
	t.upBytes.Add(int64(len(pkt)))
	storeMax(&t.upMax, int64(len(pkt)))
	if _, dport, ok := udpPorts(pkt); ok && dport == 53 {
		t.upDNS.Add(1)
	}
	f := tcpFlags(pkt)
	if f < 0 {
		return
	}
	if f&tcpFlagSyn != 0 && f&tcpFlagAck == 0 {
		t.upSyn.Add(1)
		if pkt[0]>>4 == 6 {
			t.upSyn6.Add(1)
		}
	}
	if f&tcpFlagRst != 0 {
		t.upRst.Add(1)
	}
	if f&tcpFlagFin != 0 {
		t.upFin.Add(1)
	}
}

func (t *tunnelTrace) down(pkt []byte) {
	t.downPkts.Add(1)
	t.downBytes.Add(int64(len(pkt)))
	storeMax(&t.downMax, int64(len(pkt)))
	if sport, _, ok := udpPorts(pkt); ok && sport == 53 {
		t.downDNS.Add(1)
	}
	f := tcpFlags(pkt)
	if f < 0 {
		return
	}
	if f&tcpFlagSyn != 0 && f&tcpFlagAck != 0 {
		t.downSynAck.Add(1)
	}
	if f&tcpFlagRst != 0 {
		t.downRst.Add(1)
	}
	if f&tcpFlagFin != 0 {
		t.downFin.Add(1)
	}
}

// run logs per-second deltas until ctx ends. Seconds with no traffic are skipped.
func (t *tunnelTrace) run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	started := time.Now()
	var pUp, pUpB, pDown, pDownB, pSyn, pSynAck, pRstIn, pRstOut, pFinOut, pFinIn, pErr int64
	var pDNSOut, pDNSIn, pSyn6 int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		up, upB := t.upPkts.Load(), t.upBytes.Load()
		down, downB := t.downPkts.Load(), t.downBytes.Load()
		syn, synAck := t.upSyn.Load(), t.downSynAck.Load()
		rstIn, rstOut := t.downRst.Load(), t.upRst.Load()
		finOut, finIn := t.upFin.Load(), t.downFin.Load()
		dnsOut, dnsIn, syn6 := t.upDNS.Load(), t.downDNS.Load(), t.upSyn6.Load()
		errs := t.upErrs.Load()
		if up != pUp || down != pDown || errs != pErr {
			log.Printf("trace tunnel t=%ds ip up +%d pkts/+%d B (max %d) down +%d pkts/+%d B (max %d) | dns out +%d in +%d | tcp SYN out +%d (v6 +%d) SYN-ACK in +%d RST out +%d RST in +%d FIN out +%d FIN in +%d | write errs +%d",
				int(time.Since(started).Seconds()),
				up-pUp, upB-pUpB, t.upMax.Load(), down-pDown, downB-pDownB, t.downMax.Load(),
				dnsOut-pDNSOut, dnsIn-pDNSIn,
				syn-pSyn, syn6-pSyn6, synAck-pSynAck, rstOut-pRstOut, rstIn-pRstIn, finOut-pFinOut, finIn-pFinIn,
				errs-pErr)
		}
		pUp, pUpB, pDown, pDownB = up, upB, down, downB
		pSyn, pSynAck, pRstIn, pRstOut, pFinOut, pFinIn, pErr = syn, synAck, rstIn, rstOut, finOut, finIn, errs
		pDNSOut, pDNSIn, pSyn6 = dnsOut, dnsIn, syn6
	}
}
