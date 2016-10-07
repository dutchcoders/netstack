package netstack

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	tcp "github.com/dutchcoders/netstack/tcp"
	"golang.org/x/net/ipv4"
)

type Stack struct {
	fd   int
	epfd int
	r    *rand.Rand

	m sync.Mutex

	sendQueue []SendP

	src net.IP
}

func getIPforInterface(intf string) (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		if i.Name != intf {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		// handle err
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				return v.IP
			case *net.IPAddr:
				return v.IP
			}
		}
	}

	return nil, errors.New("Interface not found.")

}

func New(intf string) (*Stack, error) {
	// for UDP -> IPPROTO_UDP
	// ETH_P_ALL

	if src, err := getIPforInterface(intf); err != nil {
		return nil, err
	} else if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP); err != nil {
		return nil, fmt.Errorf("Could not create socket: %s", err.Error())
	} else if fd < 0 {
		return nil, fmt.Errorf("Socket error: return < 0")
	} else if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	} else if epfd, err := syscall.EpollCreate1(0); err != nil {
		return nil, fmt.Errorf("epoll_create1: %s", err.Error())
	} else if err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR | syscall.EPOLL_NONBLOCK, /*| syscall.EPOLLOUT*/
		Fd:     int32(fd),
	}); err != nil {
		return nil, fmt.Errorf("epollctl: %s", err.Error())
	} else {
		r := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

		return &Stack{
			fd:   fd,
			epfd: epfd,
			r:    r,
			src:  src,
		}, nil
	}
}

func (s *Stack) Connect(dest net.IP) (*Connection, error) {
	conn := &Connection{
		Connected: make(chan bool, 1),
		Stack:     s,
		Recv:      make(chan []byte),
		Src:       s.src,
		Dst:       dest,
	}

	if err := conn.Open(s.src, dest); err != nil {
		return nil, err
	}

	// wait for ack?

	select {
	case <-time.After(30 * time.Second):
		return nil, errors.New("Timeout occured.")
	case <-conn.Connected:
		return conn, nil
	}
}

func (s *Stack) Close() {
	syscall.Close(s.epfd)
	syscall.Close(s.fd)
}

func (s Stack) Listen() (*listener, error) {
	return &listener{
		s: make(chan bool),
	}, nil
}

func (s *Stack) Start() error {
	go func() {
		var events [MaxEpollEvents]syscall.EpollEvent

		for {
			nevents, err := syscall.EpollWait(s.epfd, events[:], -1)
			if err != nil {
				fmt.Println("epoll_wait: ", err)
				break
			}

			for ev := 0; ev < nevents; ev++ {
				if events[ev].Events&syscall.EPOLLIN == syscall.EPOLLIN {
					buffer := make([]byte, DefaultBufferSize)

					if n, _, err := syscall.Recvfrom(int(events[ev].Fd), buffer, 0); err != nil {
						fmt.Println("Could not receive from descriptor: %s", err.Error())
						return
					} else if n == 0 {
						// no packets received
					} else if iph, err := ipv4.ParseHeader(buffer); err != nil {
						fmt.Println(fmt.Errorf("Error parsing ip header: ", err.Error()))
					} else if iph.Len < 5 {
						fmt.Println(fmt.Errorf("IP header length is invalid."))
					} else {
						data := buffer[20:n]

						switch iph.Protocol {
						case 6 /* tcp */ :
							if err := s.handleTCP(iph, data); err == ErrNoState {
							} else if err != nil {
								fmt.Printf("Error: %s\n", err.Error())
							}
						case 17 /* udp */ :
							if err := s.handleUDP(iph, data); err != nil {
								fmt.Printf("Error: %s\n", err.Error())
							}
						default:
							fmt.Printf("Unknown protocol: %d\n", iph.Protocol)
						}
					}
				}

				if events[ev].Events&syscall.EPOLLERR == syscall.EPOLLERR {
					//fmt.Println("EPOLLOUT")
					if v, err := syscall.GetsockoptInt(int(events[ev].Fd), syscall.SOL_SOCKET, syscall.SO_ERROR); err != nil {
						fmt.Println("Error", err)
					} else {
						fmt.Println("Error val", v)
					}
				}

				if events[ev].Events&syscall.EPOLLOUT == syscall.EPOLLOUT {
					fmt.Println("EPOLLOUT")

					s.m.Lock()
					defer s.m.Unlock()

					for _, packet := range s.sendQueue {
						fmt.Printf("Sending %d\n", len(packet.data))
						syscall.Sendto((int(events[ev].Fd)), packet.data, 0, packet.to)
					}

					s.sendQueue = []SendP{}
				}
			}
			// EPOLLOUT?
		}

	}()

	return nil
}

type SendP struct {
	data []byte
	to   syscall.Sockaddr
}

var ErrNoState = errors.New("No state for packet.")

func (s *Stack) send(data []byte, to syscall.Sockaddr) error {
	//s.m.Lock()
	//defer s.m.Unlock()
	/*
		s.sendQueue = append(s.sendQueue, SendP{
			data: data,
			to:   to,
		})

	*/

	err := syscall.Sendto(s.fd, data, 0, to)
	return err
}

func (s *Stack) handleTCP(iph *ipv4.Header, data []byte) error {
	// handle tcp

	// got tcp find state and delegate to state
	th := &tcp.Header{} // tcp.Header
	if err := th.UnmarshalWithChecksum(data, iph.Dst, iph.Src); err == tcp.ErrInvalidChecksum {
	} else if err != nil {
		fmt.Printf("err th: %s\n", err)
		return err
	}

	// add ip, tcp to state buffer
	// check states till buffer end

	state := GetState(iph, th)
	if state != nil {
	} else if false /*  listening on port */ {
	} else {
		// fmt.Printf("No state for: %#v\n", th)
		// SEND RST?
		// no sta
		return ErrNoState
	}

	func() {
		state.Lock()
		defer state.Unlock()

		// fmt.Printf("<- %s %d %d %d %d\n", state.SocketState, state.ID, th.SeqNum, th.AckNum, th.Ctrl)

		if th.HasFlag(tcp.RST) {
			// todo: ack?
			// fmt.Println("Connection resetted")
			if !state.Conn.closed {
				state.Conn.closed = true
				close(state.Conn.Recv)
			}

			state.SocketState = SocketClosed
			return
		}

		transmissionQueue := []tcp.Header{}

		// should we ignore packets out of sequence?

		// add to transmission queue
		// retransmit everything after last ack num
		//  after timeout again
		// first ack
		// if PSH then push, otherwise buffer, for now we're just pushing.
		if state.SocketState == SocketSynSent {
			if th.HasFlag(tcp.SYN | tcp.ACK) {
			} else {
				fmt.Printf("StateSynSent: unexpected ctrl %d\n", th.Ctrl)
				state.SocketState = SocketClosed
				return
			}

			// check sendnext / recvnext sequence numbers
			state.RecvNext = th.SeqNum + 1

			state.LastAcked = state.RecvNext

			th := tcp.Header{
				Source:      th.Destination,
				Destination: th.Source,
				SeqNum:      state.SendNext,
				AckNum:      state.RecvNext,
				DataOffset:  5,
				Reserved:    0,
				ECN:         0,
				Ctrl:        tcp.ACK,
				Window:      64420,
				Checksum:    0,
				Urgent:      0,
				Options:     []*tcp.Option{},
				Payload:     []byte{},
			}

			transmissionQueue = append(transmissionQueue, th)

			defer func() {
				state.Conn.Connected <- true
			}()

			state.SocketState = SocketEstablished
		} else if state.SocketState == SocketEstablished {
			if th.HasFlag(tcp.PSH) {
				// state.Conn.Flush()
			}

			// how to identify wrong flags /packets?
			// send rst

			if th.Ctrl == tcp.ACK {
				// ignore single acks
				// fmt.Println("Got single ack", th.SeqNum, th.AckNum)
			} else {

				// ACKNowledge received packet, for fin, psh
				if true /*th.HasFlag(PSH) || th.HasFlag(FIN)*/ && state.RecvNext <= th.SeqNum {
					state.RecvNext = th.SeqNum + uint32(len(th.Payload))

					if th.HasFlag(tcp.FIN) {
						state.RecvNext = state.RecvNext + 1
					}

					state.LastAcked = state.RecvNext

					th := tcp.Header{
						Source:      th.Destination,
						Destination: th.Source,
						SeqNum:      state.SendNext,
						AckNum:      state.RecvNext,
						DataOffset:  5,
						Reserved:    0,
						ECN:         0,
						Ctrl:        tcp.ACK,
						Window:      64420,
						Checksum:    0,
						Urgent:      0,
						Options:     []*tcp.Option{},
						Payload:     []byte{},
					}

					transmissionQueue = append(transmissionQueue, th)
					// fmt.Println("sending ACK", state.RecvNext, th.SeqNum)
				} else {
					// fmt.Println("Not sending ACK", state.RecvNext, th.SeqNum)
				}

				if th.HasFlag(tcp.FIN) {

					state.LastAcked = state.RecvNext

					th := tcp.Header{
						Source:      th.Destination,
						Destination: th.Source,
						SeqNum:      state.SendNext,
						AckNum:      state.RecvNext,
						DataOffset:  5,
						Reserved:    0,
						ECN:         0,
						Ctrl:        tcp.FIN,
						Window:      64420,
						Checksum:    0,
						Urgent:      0,
						Options:     []*tcp.Option{},
						Payload:     []byte{},
					}

					state.SendNext++

					transmissionQueue = append(transmissionQueue, th)

					state.SocketState = SocketLastAck // return CloseWait()?
				}
			}
		} else if state.SocketState == SocketFinWait1 {
			if th.HasFlag(tcp.FIN) {
				// send ack
				/*
					if th.Ctrl == SYN|ACK {
					} else {
						fmt.Printf("SocketFinWait1: unexpected ctrl %d\n", th.Ctrl)
						// send reset?
						state.SocketState = SocketClosed
						return
					}
				*/

				state.RecvNext = th.SeqNum + 1

				state.LastAcked = th.SeqNum

				th := tcp.Header{
					Source:      th.Destination,
					Destination: th.Source,
					SeqNum:      state.SendNext,
					AckNum:      state.RecvNext,
					DataOffset:  5,
					Reserved:    0,
					ECN:         0,
					Ctrl:        tcp.ACK,
					Window:      64420,
					Checksum:    0,
					Urgent:      0,
					Options:     []*tcp.Option{},
					Payload:     []byte{},
				}

				transmissionQueue = append(transmissionQueue, th)

				state.SendNext++

				state.SocketState = SocketClosing
			} else if th.HasFlag(tcp.ACK) {
				//
				state.SocketState = SocketFinWait2
			}

			// send ack

		} else if state.SocketState == SocketFinWait2 {
			if true /*th.HasFlag(PSH) || th.HasFlag(FIN)*/ && state.RecvNext <= th.SeqNum {
				state.RecvNext = th.SeqNum + uint32(len(th.Payload))
				if th.HasFlag(tcp.FIN) {
					state.RecvNext = th.SeqNum + uint32(len(th.Payload)) + 1

				}

				state.LastAcked = state.RecvNext

				th := tcp.Header{
					Source:      th.Destination,
					Destination: th.Source,
					SeqNum:      state.SendNext,
					AckNum:      state.RecvNext,
					DataOffset:  5,
					Reserved:    0,
					ECN:         0,
					Ctrl:        tcp.ACK,
					Window:      64420,
					Checksum:    0,
					Urgent:      0,
					Options:     []*tcp.Option{},
					Payload:     []byte{},
				}

				transmissionQueue = append(transmissionQueue, th)

				state.SocketState = SocketClosing
			}

			if th.HasFlag(tcp.FIN) {
				// PSH /ACK
				// GOT delayed DATA
				defer func() {
					if !state.Conn.closed {
						state.Conn.closed = true
						close(state.Conn.Recv)
					}
				}()
			} else {
				// fmt.Println("SocketFinWait2: expected fin, got %d %d %d", th.Ctrl, th.AckNum, th.SeqNum)

			}
		} else if state.SocketState == SocketLastAck {
			if !th.HasFlag(tcp.ACK) {
			}

			if true /*th.HasFlag(PSH) || th.HasFlag(FIN)*/ && state.RecvNext <= th.SeqNum {
				// fmt.Println("SocketLastAck: Acked!")
			}

			defer func() {
				fmt.Println("CLosed Last ack", iph.Src.String())
				if !state.Conn.closed {
					state.Conn.closed = true
					close(state.Conn.Recv)
				}
			}()

			state.SocketState = SocketTimeWait
		} else if state.SocketState == SocketClosing {
			// receive ack of fin
			if th.HasFlag(tcp.ACK) {
				defer func() {
					if !state.Conn.closed {
						state.Conn.closed = true
						close(state.Conn.Recv)
					}
				}()

				state.SocketState = SocketTimeWait

			} else if true /*th.HasFlag(PSH) || th.HasFlag(FIN)*/ && state.RecvNext <= th.SeqNum {
				// fmt.Println("SocketLastAck: Acked!")
			}

			//defer close(state.Conn.Recv)
		} else if state.SocketState == SocketTimeWait {
			// timeout
			// then socketstate -> socketclosed
		} else if state.SocketState == SocketClosed {
			fmt.Println("Got packets on closed socket.")
		}

		defer func() {
			if len(th.Payload) == 0 {
			} else if state.Conn.closed {
				fmt.Println("Got Payload, but conn closed", iph.Src.String(), string(th.Payload))
			} else {
				// fmt.Println("Payload", iph.Src.String(), iph.Dst.String(), string(th.Payload))
				state.Conn.buffer = append(state.Conn.buffer, th.Payload[:]...)

				// non blocking send
				select {
				case state.Conn.Recv <- []byte{}:
				default:
				}
			}
		}()

		s.m.Lock()
		defer s.m.Unlock()

		for _, th := range transmissionQueue {
			iph := ipv4.Header{
				Version:  4,
				Len:      20,
				TOS:      0,
				TotalLen: 52,
				Flags:    2,
				TTL:      128,
				Protocol: 6,
				Src:      iph.Dst,
				Dst:      iph.Src,
				Options:  []byte{},
				ID:       state.ID,
			}

			data, err := iph.Marshal()
			if err != nil {
				log.Printf("Error sendto: %#v", err.Error())
			}

			data2, err := th.MarshalWithChecksum(iph.Dst, iph.Src)
			if err != nil {
				log.Printf("Error sendto: %#v", err.Error())
			}

			data = append(data, data2...)

			// dump("send packet", data, layers.LayerTypeIPv4)

			to := &syscall.SockaddrInet4{Port: int(0), Addr: to4byte(iph.Dst.String())} //[4]byte{dest[0], dest[1], dest[2], dest[3]}}

			/*
				// should we do EPOLLOUT?

				err = syscall.Sendto(s.fd, data, 0, to)
				if err != nil {
					log.Printf("Error sendto: %#v\n", err.Error())
				}

			*/
			// fmt.Printf("-> %s %d %d %d %d\n", state.SocketState, state.ID, th.SeqNum, th.AckNum, th.Ctrl)

			s.send(data, to)

			state.ID++
		}

	}()

	return nil
}

func (s *Stack) handleUDP(iph *ipv4.Header, data []byte) error {
	return nil
	/*
		hdr := &udp.Header{} // tcp.Header
		hdr.Unmarshal(data)

		// remove checksum, should be recalculated
		hdr.Checksum = 0

		// currently only interested in
		if hdr.Source != 53 && hdr.Destination != 53 {
			fmt.Println("Ignoring port")
			return
		}

		if iph.Src.Equal(net.ParseIP("8.8.8.8")) {
			iph.Src = iph.Dst
			iph.Dst = net.ParseIP("172.16.84.1")
		} else if iph.Src.Equal(net.ParseIP("172.16.84.1")) {
			iph.Src = iph.Dst
			iph.Dst = net.ParseIP("8.8.8.8")
		} else {
			fmt.Println("Unknown traffic", iph.Src.String(), net.ParseIP("172.168.84.1").String())
			return
		}

		// do we have active sockets?
		// send to socket
		// check source address, port with destination address, port

		client := UDPConn{
			closed:      false,
			readBuffer:  hdr.Payload,
			writeBuffer: []byte{},
			iph:         iph,
			hdr:         hdr,
			s:           s,
		}

		server := UDPConn{
			closed:      false,
			readBuffer:  []byte{},
			writeBuffer: []byte{},
			iph:         iph,
			hdr:         hdr,
			s:           s,
		}

		if err := Proxy(&client, &server); err != nil {
			log.Printf("Error proxy: %#v\n", err.Error())
		}
	*/
}
