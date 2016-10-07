/*
Copyright 2013-2014 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
*/

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type Flag uint8

const (
	FIN Flag = 1  // 00 0001
	SYN      = 2  // 00 0010
	RST      = 4  // 00 0100
	PSH      = 8  // 00 1000
	ACK      = 16 // 01 0000
	URG      = 32 // 10 0000
)

type Header struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 3 bits
	ECN         uint8 // 3 bits
	Ctrl        Flag  // 6 bits
	Window      uint16
	Checksum    uint16 // Kernel will set this if it's 0
	Urgent      uint16
	Options     []*Option
	Payload     []byte
}

type Option struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

var ErrInvalidChecksum = fmt.Errorf("Invalid checksum")

func (hdr *Header) UnmarshalWithChecksum(data []byte, src, dest net.IP) error {
	err := hdr.Unmarshal(data)

	checksum := csum(data, to4byte(src.String()), to4byte(dest.String()))
	if checksum != hdr.Checksum {
		return ErrInvalidChecksum
	}

	return err
}

func Parse(data []byte) (Header, error) {
	h := Header{}
	return h, h.Unmarshal(data)
}

func (hdr *Header) Unmarshal(data []byte) error {
	// TODO: don't use the reader for this
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &hdr.Source)
	binary.Read(r, binary.BigEndian, &hdr.Destination)
	binary.Read(r, binary.BigEndian, &hdr.SeqNum)
	binary.Read(r, binary.BigEndian, &hdr.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	hdr.DataOffset = byte(mix >> 12)  // top 4 bits
	hdr.Reserved = byte(mix >> 9 & 7) // 3 bits
	hdr.ECN = byte(mix >> 6 & 7)      // 3 bits
	hdr.Ctrl = Flag(byte(mix & 0x3f)) // bottom 6 bits

	binary.Read(r, binary.BigEndian, &hdr.Window)
	binary.Read(r, binary.BigEndian, &hdr.Checksum)
	binary.Read(r, binary.BigEndian, &hdr.Urgent)

	if hdr.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", hdr.DataOffset)
	}

	dataStart := int(hdr.DataOffset) * 4

	data = make([]byte, dataStart-20)

	if _, err := r.Read(data); err != nil {
		return err
	}

	hdr.Options = []*Option{}

	for len(data) > 0 {

		opt := &Option{Kind: data[0]}
		hdr.Options = append(hdr.Options, opt)

		switch opt.Kind {
		case 0: // End of options
			opt.Length = 1
			// tcp.Padding = data[1:]
			break
		case 1: // 1 byte padding
			opt.Length = 1
		default:
			opt.Length = data[1]
			if opt.Length < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.Length)
			} else if int(opt.Length) > len(data) {
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.Length, len(data))
			}
			opt.Data = data[2:opt.Length]
		}

		data = data[opt.Length:]
	}

	// fmt.Printf("Options %#v\n", tcp.Options)

	hdr.Payload = make([]byte, r.Len())

	_, err := r.Read(hdr.Payload)
	return err
}

func (hdr *Header) HasFlag(flagBit Flag) bool {
	return hdr.Ctrl&flagBit != 0
}

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

func (hdr *Header) CalcChecksum(src, dest net.IP) uint16 {
	return 0 //csum(data, to4byte(src.String()), to4byte(dest.String()))
}

func (hdr *Header) MarshalWithChecksum(src, dest net.IP) ([]byte, error) {
	data, err := hdr.Marshal()
	checksum := csum(data, to4byte(src.String()), to4byte(dest.String()))
	data[16] = byte(checksum >> 8)
	data[17] = byte(checksum & 0xFF)
	return data, err
}

func (hdr *Header) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, hdr.Source)
	binary.Write(buf, binary.BigEndian, hdr.Destination)
	binary.Write(buf, binary.BigEndian, hdr.SeqNum)
	binary.Write(buf, binary.BigEndian, hdr.AckNum)

	var mix uint16
	mix = uint16(hdr.DataOffset)<<12 | // top 4 bits
		uint16(hdr.Reserved)<<9 | // 3 bits
		uint16(hdr.ECN)<<6 | // 3 bits
		uint16(hdr.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, hdr.Window)
	binary.Write(buf, binary.BigEndian, hdr.Checksum)
	binary.Write(buf, binary.BigEndian, hdr.Urgent)

	for _, option := range hdr.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := uint8(hdr.DataOffset*4) - uint8(len(out))
	for i := uint8(0); i < pad; i++ {
		out = append(out, 0)
	}

	//	binary.Write(buf, binary.BigEndian, tcp.Payload)
	out = append(out, hdr.Payload...)

	return out, nil
}

// TCP Checksum
func csum(data []byte, srcip, dstip [4]byte) uint16 {
	csum := uint32(0)

	csum += (uint32(srcip[0]) << 8) + uint32(srcip[1])
	csum += (uint32(srcip[2]) << 8) + uint32(srcip[3])
	csum += (uint32(dstip[0]) << 8) + uint32(dstip[1])
	csum += (uint32(dstip[2]) << 8) + uint32(dstip[3])

	csum += uint32(6)

	length := uint32(len(data))
	csum += uint32(length)

	for i := uint32(0); i+1 < length; i += 2 {
		// skip checksum
		if i == 16 {
			continue
		}

		csum += uint32(uint16(data[i])<<8 + uint16(data[i+1]))
	}

	if len(data)%2 == 1 {
		csum += uint32(data[len(data)-1]) << 8
	}

	for csum>>16 > 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}

	return uint16(^csum)
}
