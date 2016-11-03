package main

// +build amd64,linux

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/dutchcoders/netstack"
)

func main() {
	var u *url.URL

	if v, err := url.Parse(os.Args[1]); err != nil {
		panic(err)
	} else {
		u = v
	}

	var s *netstack.Stack
	if v, err := netstack.New("eth0"); err != nil {
		panic(err)
	} else {
		s = v
	}

	// start the stack
	s.Start()
	defer s.Close()

	fmt.Printf("Connecting to host: %s\n", u.Host)

	var ip net.IP
	if addr, err := net.ResolveIPAddr("ip4", u.Host); err != nil {
		panic(err)
	} else {
		ip = addr.IP
	}

	fmt.Printf("Connecting to ip: %s\n", ip.String())

	var conn net.Conn
	if v, err := s.Connect(ip, 80); err != nil {
		panic(err)
	} else {
		conn = v
	}

	request, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		fmt.Printf("New request %s: %s\n", u.String(), err.Error())
		return
	}

	if err := request.Write(conn); err != nil {
		fmt.Printf("Connection write %s: %s\n", u.String(), err.Error())
		return
	}

	r := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(r, nil); err != nil {
		fmt.Println("Read response %s: %s\n", u.String(), err.Error())
		return
	} else if b, err := httputil.DumpResponse(resp, false); err != nil {
		panic(err)
	} else {
		fmt.Println(string(b))
	}
}
