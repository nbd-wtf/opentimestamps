package opentimestamps

import (
	"io"
	"strings"
)

func normalizeUrl(u string) string {
	if strings.HasSuffix(u, "/") {
		u = u[0 : len(u)-1]
	}
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		u = "http://" + u
	}
	return u
}

type Buffer struct {
	pos *int
	buf []byte
}

func NewBuffer(buf []byte) Buffer {
	zero := 0
	return Buffer{&zero, buf}
}

func (buf Buffer) readBytes(n int) ([]byte, error) {
	// fmt.Println("reading", n, "bytes")
	if *buf.pos >= len(buf.buf) {
		return nil, io.EOF
	}
	res := buf.buf[*buf.pos : *buf.pos+n]
	*buf.pos = *buf.pos + n
	// fmt.Println("->", hex.EncodeToString(res))
	return res, nil
}

func (buf Buffer) readByte() (byte, error) {
	b, err := buf.readBytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (buf Buffer) readVarUint() (uint64, error) {
	var value uint64 = 0
	var shift uint64 = 0

	for {
		b, err := buf.readByte()
		if err != nil {
			return 0, err
		}
		value |= (uint64(b) & 0b01111111) << shift
		shift += 7
		if b&0b10000000 == 0 {
			break
		}
	}
	return value, nil
}

func (buf Buffer) readVarBytes() ([]byte, error) {
	v, err := buf.readVarUint()
	if err != nil {
		return nil, err
	}
	b, err := buf.readBytes(int(v))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func appendVarUint(buf []byte, value uint64) []byte {
	if value == 0 {
		buf = append(buf, 0)
	} else {
		for value != 0 {
			b := byte(value & 0b01111111)
			if value > 0b01111111 {
				b |= 0b10000000
			}
			buf = append(buf, b)
			if value <= 0b01111111 {
				break
			}
			value >>= 7
		}
	}

	return buf
}

func appendVarBytes(buf []byte, value []byte) []byte {
	buf = appendVarUint(buf, uint64(len(value)))
	buf = append(buf, value...)
	return buf
}
