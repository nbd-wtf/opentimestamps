package opentimestamps

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/exp/slices"
)

/*
 * Header magic bytes
 * Designed to be give the user some information in a hexdump, while being identified as 'data' by the file utility.
 * \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94
 */
var headerMagic = []byte{0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94}

var (
	pendingMagic = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	bitcoinMagic = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
)

type Operation struct {
	Name   string
	Tag    byte
	Binary bool // it's an operation that takes one argument, otherwise takes none
	Apply  func(curr []byte, arg []byte) []byte
}

var tags = map[byte]*Operation{
	0xf0: {"append", 0xf0, true, func(curr []byte, arg []byte) []byte { return append(curr, arg...) }},
	0xf1: {"prepend", 0xf1, true, func(curr []byte, arg []byte) []byte { return append(arg, curr...) }},
	0xf2: {"reverse", 0xf2, false, func(curr []byte, arg []byte) []byte { panic("reverse not implemented") }},
	0xf3: {"hexlify", 0xf3, false, func(curr []byte, arg []byte) []byte { panic("hexlify not implemented") }},
	0x02: {"sha1", 0x02, false, func(curr []byte, arg []byte) []byte { panic("sha1 not implemented") }},
	0x03: {"ripemd160", 0x03, false, func(curr []byte, arg []byte) []byte { panic("ripemd160 not implemented") }},
	0x08: {"sha256", 0x08, false, func(curr []byte, arg []byte) []byte {
		v := sha256.Sum256(curr)
		return v[:]
	}},
	0x67: {"keccak256", 0x67, false, func(curr []byte, arg []byte) []byte { panic("keccak256 not implemented") }},
}

type Timestamp struct {
	Digest       []byte
	Instructions [][]Instruction
}

type Instruction struct {
	*Operation
	Argument []byte
	*Attestation
}

type Attestation struct {
	Name               string
	BitcoinBlockHeight uint64
	CalendarServerURL  string
}

func parseCalendarServerResponse(buf Buffer, digest []byte) (Timestamp, error) {
	ts := Timestamp{
		Digest: digest,
	}

	err := parseTimestamp(buf, &ts)
	if err != nil {
		return ts, err
	}

	return ts, nil
}

func parseOTSFile(buf Buffer) (Timestamp, error) {
	ts := Timestamp{}

	// read magic
	// read version [1 byte]
	// read crypto operation for file digest [1 byte]
	// read file digest [32 byte (depends)]
	if magic, err := buf.readBytes(len(headerMagic)); err != nil || slices.Equal(headerMagic, magic) {
		return ts, fmt.Errorf("invalid ots file header '%s': %w", magic, err)
	}

	if version, err := buf.readByte(); err != nil || version != '1' {
		return ts, fmt.Errorf("invalid ots file version '%v': %w", version, err)
	}

	tag, err := buf.readByte()
	if err != nil {
		return ts, fmt.Errorf("failed to read operation byte: %w", err)
	}

	if op, err := readInstruction(buf, tag); err != nil || op.Operation.Name != "sha256" {
		return ts, fmt.Errorf("invalid crypto operation '%v', only sha256 supported: %w", op, err)
	}

	if err := parseTimestamp(buf, &ts); err != nil {
		return ts, err
	}

	return ts, nil
}

func parseTimestamp(buf Buffer, ts *Timestamp) error {
	// read instructions
	//   if operation = push
	//   if 0x00 = attestation
	//      read tag [8 bytes]
	//      readvarbytes
	//        interpret these depending on the type of attestation
	//          if bitcoin: readvaruint as the block height
	//          if pending from calendar: readvarbytes as the utf-8 calendar url
	//   if 0xff = skip and start reading a new block of instructions?

	currInstructionsBlock := 0
	ts.Instructions = make([][]Instruction, 0, 5)

	// start first instruction block
	ts.Instructions = append(ts.Instructions, make([]Instruction, 0, 30))

	// go read these tags
	for {
		tag, err := buf.readByte()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read operation byte: %w", err)
		}

		if tag == 0x00 {
			// enter an attestation context
			magic, err := buf.readBytes(8)
			if err != nil {
				return fmt.Errorf("failed to read attestion magic bytes: %w", err)
			}

			this, err := buf.readVarBytes()
			if err != nil {
				return fmt.Errorf("failed to read attestation bytes: %w", err)
			}
			abuf := NewBuffer(this)

			switch {
			case slices.Equal(magic, pendingMagic):
				val, err := abuf.readVarBytes()
				if err != nil {
					return fmt.Errorf("failed reading calendar server url: %w", err)
				}
				ts.Instructions[currInstructionsBlock] = append(
					ts.Instructions[currInstructionsBlock],
					Instruction{Attestation: &Attestation{Name: "pending", CalendarServerURL: string(val)}},
				)
				continue
			case slices.Equal(magic, bitcoinMagic):
				val, err := abuf.readVarUint()
				if err != nil {
					return fmt.Errorf("failed reading bitcoin block number: %w", err)
				}
				ts.Instructions[currInstructionsBlock] = append(
					ts.Instructions[currInstructionsBlock],
					Instruction{Attestation: &Attestation{Name: "bitcoin", BitcoinBlockHeight: val}},
				)
				continue
			default:
				return fmt.Errorf("unsupported attestation type %v", magic)
			}
		} else if tag == 0xff {
			// another block of instructions
			ts.Instructions = append(ts.Instructions, make([]Instruction, 0, 30))
			currInstructionsBlock++
			tag, err = buf.readByte()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("failed to read operation byte when starting a new block of instructions: %w", err)
			}
		}

		// a new operation in this block
		inst, err := readInstruction(buf, tag)
		if err != nil {
			return fmt.Errorf("failed to read instruction: %w", err)
		}

		ts.Instructions[currInstructionsBlock] = append(ts.Instructions[currInstructionsBlock], *inst)
	}
}

func readInstruction(buf Buffer, tag byte) (*Instruction, error) {
	op, ok := tags[tag]
	if !ok {
		return nil, fmt.Errorf("unknown tag %v", tag)
	}

	inst := Instruction{
		Operation: op,
	}

	if op.Binary {
		val, err := buf.readVarBytes()
		if err != nil {
			return nil, fmt.Errorf("error reading argument: %w", err)
		}
		inst.Argument = val
	}

	return &inst, nil
}
