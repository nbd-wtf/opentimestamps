package opentimestamps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const maxResultLength = 4096

type (
	unaryMsgOp  func(message []byte) ([]byte, error)
	binaryMsgOp func(message, argument []byte) ([]byte, error)
)

// msgAppend returns the concatenation of msg and arg
func msgAppend(msg, arg []byte) (res []byte, err error) {
	res = append(res, msg...)
	res = append(res, arg...)
	return
}

// msgPrepend returns the concatenation of arg and msg
func msgPrepend(msg, arg []byte) (res []byte, err error) {
	res = append(res, arg...)
	res = append(res, msg...)
	return
}

// msgReverse returns the reversed msg. Deprecated.
func msgReverse(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, fmt.Errorf("empty input invalid for msgReverse")
	}
	res := make([]byte, len(msg))
	for i, b := range msg {
		res[len(res)-i-1] = b
	}
	return res, nil
}

func msgHexlify(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, fmt.Errorf("empty input invalid for msgHexlify")
	}
	return []byte(hex.EncodeToString(msg)), nil
}

type opCode interface {
	match(byte) bool
	decode(*deserializationContext) (opCode, error)
	encode(*serializationContext) error
	apply(message []byte) ([]byte, error)
}

type op struct {
	tag  byte
	name string
}

func (o op) match(tag byte) bool {
	return o.tag == tag
}

type unaryOp struct {
	op
	msgOp unaryMsgOp
}

func newUnaryOp(tag byte, name string, msgOp unaryMsgOp) *unaryOp {
	return &unaryOp{op{tag: tag, name: name}, msgOp}
}

func (u *unaryOp) String() string {
	return u.name
}

func (u *unaryOp) decode(ctx *deserializationContext) (opCode, error) {
	ret := *u
	return &ret, nil
}

func (u *unaryOp) encode(ctx *serializationContext) error {
	return ctx.writeByte(u.tag)
}

func (u *unaryOp) apply(message []byte) ([]byte, error) {
	return u.msgOp(message)
}

// Binary operations
// We decode an extra varbyte argument and use it in apply()

type binaryOp struct {
	op
	msgOp    binaryMsgOp
	argument []byte
}

func newBinaryOp(tag byte, name string, msgOp binaryMsgOp) *binaryOp {
	return &binaryOp{
		op:       op{tag: tag, name: name},
		msgOp:    msgOp,
		argument: nil,
	}
}

func (b *binaryOp) decode(ctx *deserializationContext) (opCode, error) {
	arg, err := ctx.readVarBytes(0, maxResultLength)
	if err != nil {
		return nil, err
	}
	if len(arg) == 0 {
		return nil, fmt.Errorf("empty argument invalid for binaryOp")
	}
	ret := *b
	ret.argument = arg
	return &ret, nil
}

func (b *binaryOp) encode(ctx *serializationContext) error {
	if err := ctx.writeByte(b.tag); err != nil {
		return err
	}
	return ctx.writeVarBytes(b.argument)
}

func (b *binaryOp) apply(message []byte) ([]byte, error) {
	return b.msgOp(message, b.argument)
}

func (b *binaryOp) String() string {
	return fmt.Sprintf("%s %x", b.name, b.argument)
}

func msgSHA256(msg []byte) ([]byte, error) {
	res := sha256.Sum256(msg)
	return res[:], nil
}

var (
	opAppend  = newBinaryOp(0xf0, "APPEND", msgAppend)
	opPrepend = newBinaryOp(0xf1, "PREPEND", msgPrepend)
	opReverse = newUnaryOp(0xf2, "REVERSE", msgReverse)
	opHexlify = newUnaryOp(0xf3, "HEXLIFY", msgHexlify)
	opSHA256  = newUnaryOp(0x08, "SHA256", msgSHA256)
)

var opCodes []opCode = []opCode{opAppend, opPrepend, opReverse, opHexlify, opSHA256}

func parseOp(ctx *deserializationContext, tag byte) (opCode, error) {
	for _, op := range opCodes {
		if op.match(tag) {
			return op.decode(ctx)
		}
	}
	return nil, fmt.Errorf("could not decode tag %02x", tag)
}
