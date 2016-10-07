package netstack

// +build amd64,linux

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	tcp "github.com/dutchcoders/netstack/tcp"
	"golang.org/x/net/ipv4"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

const (
	MaxEpollEvents    = 2048
	DefaultBufferSize = 65535
)

type SocketState int

const (
	SocketClosed SocketState = iota
	SocketListen
	SocketSynReceived
	SocketSynSent
	SocketEstablished
	SocketFinWait1
	SocketFinWait2
	SocketClosing
	SocketTimeWait
	SocketCloseWait
	SocketLastAck
)

func (ss SocketState) String() string {
	switch ss {
	case SocketClosed:
		return "SocketClosed"
	case SocketListen:
		return "SocketListen"
	case SocketSynReceived:
		return "SocketSynReceived"
	case SocketSynSent:
		return "SocketSynSent"
	case SocketEstablished:
		return "SocketEstablished"
	case SocketFinWait1:
		return "SocketFinWait1"
	case SocketFinWait2:
		return "SocketFinWait2"
	case SocketClosing:
		return "SocketClosing"
	case SocketTimeWait:
		return "SocketTimeWait"
	case SocketCloseWait:
		return "SocketCloseWait"
	case SocketLastAck:
		return "SocketLastAck"
	default:
		return fmt.Sprintf("Unknown state: %d", int(ss))
	}
}

type State struct {
	sync.Mutex

	SrcIP    net.IP
	SrcPort  uint16
	DestIP   net.IP
	DestPort uint16

	Last time.Time

	RecvNext           uint32
	SendNext           uint32
	SendUnAcknowledged uint32
	LastAcked          uint32

	SocketState SocketState

	ID int

	Conn *Connection
}

// GetState will return the state for the ip, port combination
func GetState(ipLayer *ipv4.Header, tcpLayer *tcp.Header) *State {
	SrcIP := ipLayer.Src
	SrcPort := tcpLayer.Source
	DestIP := ipLayer.Dst
	DestPort := tcpLayer.Destination

	for _, state := range stateTable {
		// closed connections
		if state.SocketState == SocketTimeWait {
			continue
		}

		if state.SrcPort != SrcPort && state.DestPort != SrcPort {
			continue
		}
		if state.DestPort != DestPort && state.SrcPort != DestPort {
			continue
		}
		// comparing ipv6 with ipv4 now
		if !state.SrcIP.Equal(SrcIP) && !state.DestIP.Equal(SrcIP) {
			continue
		}
		if !state.DestIP.Equal(DestIP) && !state.SrcIP.Equal(DestIP) {
			continue
		}

		return state
	}

	return nil
}

var stateTable []*State

func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

type socket struct {
}

type listener struct {
	s chan bool
}

func (l *listener) Accept() (socket, error) {
	<-l.s

	// wait for packets to arrive. Return a socket
	return socket{}, nil
}
