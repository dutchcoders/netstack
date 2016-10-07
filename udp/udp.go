package udp

import "encoding/binary"

type Header struct {
	Source      uint16
	Destination uint16
	Length      uint16
	Checksum    uint16
	Payload     []byte
}

func (hdr *Header) Unmarshal(data []byte) error {
	hdr.Source = binary.BigEndian.Uint16(data[0:2])
	hdr.Destination = binary.BigEndian.Uint16(data[2:4])
	hdr.Length = binary.BigEndian.Uint16(data[4:6])
	hdr.Checksum = binary.BigEndian.Uint16(data[6:8])
	hdr.Payload = data[8:]
	return nil
}

func (hdr *Header) Marshal() ([]byte, error) {
	buf := make([]byte, 8+len(hdr.Payload))
	binary.BigEndian.PutUint16(buf[0:2], hdr.Source)
	binary.BigEndian.PutUint16(buf[2:4], hdr.Destination)
	binary.BigEndian.PutUint16(buf[4:6], hdr.Length)
	binary.BigEndian.PutUint16(buf[6:8], hdr.Checksum)
	copy(buf[8:], hdr.Payload)
	return buf, nil
}
