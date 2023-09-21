package opentimestamps

import (
	"encoding/hex"
	"fmt"
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
	fmt.Println("reading", n, "bytes")

	if *buf.pos >= len(buf.buf) {
		return nil, io.EOF
	}
	res := buf.buf[*buf.pos : *buf.pos+n]
	*buf.pos = *buf.pos + n
	fmt.Println("->", hex.EncodeToString(res))
	return res, nil
}

func (buf Buffer) readByte() (byte, error) {
	fmt.Println("reading byte")

	b, err := buf.readBytes(1)
	if err != nil {
		return 0, err
	}
	fmt.Println("->", hex.EncodeToString(b))
	return b[0], nil
}

func (buf Buffer) readVarUint() (uint64, error) {
	fmt.Println("reading varuint")

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

	fmt.Println("->", value, "(num)")
	return value, nil
}

func (buf Buffer) readVarBytes() ([]byte, error) {
	fmt.Println("reading varbytes")

	v, err := buf.readVarUint()
	if err != nil {
		return nil, err
	}

	b, err := buf.readBytes(int(v))
	if err != nil {
		return nil, err
	}

	fmt.Println("->", hex.EncodeToString(b))
	return b, nil
}
