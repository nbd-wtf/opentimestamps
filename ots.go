package opentimestamps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

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
	BitcoinBlockHeight uint64
	CalendarServerURL  string
}

func (att Attestation) Name() string {
	if att.BitcoinBlockHeight != 0 {
		return "bitcoin"
	} else if att.CalendarServerURL != "" {
		return "pending"
	} else {
		return "unknown/broken"
	}
}

func (att Attestation) String() string {
	if att.BitcoinBlockHeight != 0 {
		return fmt.Sprintf("bitcoin(%d)", att.BitcoinBlockHeight)
	} else if att.CalendarServerURL != "" {
		return fmt.Sprintf("pending(%s)", att.CalendarServerURL)
	} else {
		return "unknown/broken"
	}
}

func parseCalendarServerResponse(buf Buffer, digest []byte) (*Timestamp, error) {
	ts := &Timestamp{
		Digest: digest,
	}

	err := parseTimestamp(buf, ts)
	if err != nil {
		return nil, err
	}

	return ts, nil
}

func parseOTSFile(buf Buffer) (*Timestamp, error) {
	// read magic
	// read version [1 byte]
	// read crypto operation for file digest [1 byte]
	// read file digest [32 byte (depends)]
	if magic, err := buf.readBytes(len(headerMagic)); err != nil || !slices.Equal(headerMagic, magic) {
		return nil, fmt.Errorf("invalid ots file header '%s': %w", magic, err)
	}

	if version, err := buf.readVarUint(); err != nil || version != 1 {
		return nil, fmt.Errorf("invalid ots file version '%v': %w", version, err)
	}

	tag, err := buf.readByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read operation byte: %w", err)
	}

	if op, err := readInstruction(buf, tag); err != nil || op.Operation.Name != "sha256" {
		return nil, fmt.Errorf("invalid crypto operation '%v', only sha256 supported: %w", op, err)
	}

	// if we got here assume the digest is sha256
	digest, err := buf.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read 32-byte digest: %w", err)
	}

	ts := &Timestamp{
		Digest: digest,
	}

	if err := parseTimestamp(buf, ts); err != nil {
		return nil, err
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
	//      end or go back to last continuation byte
	//   if 0xff = pick up a continuation byte (checkpoint) and add it to stack

	currInstructionsBlock := 0
	ts.Instructions = make([][]Instruction, 0, 10)

	// we will store checkpoints here
	checkpoints := make([][]Instruction, 0, 4)

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
					Instruction{Attestation: &Attestation{CalendarServerURL: string(val)}},
				)
			case slices.Equal(magic, bitcoinMagic):
				val, err := abuf.readVarUint()
				if err != nil {
					return fmt.Errorf("failed reading bitcoin block number: %w", err)
				}
				ts.Instructions[currInstructionsBlock] = append(
					ts.Instructions[currInstructionsBlock],
					Instruction{Attestation: &Attestation{BitcoinBlockHeight: val}},
				)
			default:
				return fmt.Errorf("unsupported attestation type '%x': %x", magic, this)
			}

			// check if we have checkpoints and, if yes, copy them in a new block of instructions
			ncheckpoints := len(checkpoints)
			if ncheckpoints > 0 {
				// use this checkpoint as the starting point for the next block
				cp := checkpoints[ncheckpoints-1]
				checkpoints = checkpoints[0 : ncheckpoints-1] // remove this from the stack
				ts.Instructions = append(ts.Instructions, cp)
				currInstructionsBlock++
			}
		} else if tag == 0xff {
			// pick up a checkpoint to be used later
			currentBlock := ts.Instructions[currInstructionsBlock]
			cp := make([]Instruction, len(currentBlock))
			copy(cp, currentBlock)
			checkpoints = append(checkpoints, cp)
		} else {
			// a new operation in this block
			inst, err := readInstruction(buf, tag)
			if err != nil {
				return fmt.Errorf("failed to read instruction: %w", err)
			}
			ts.Instructions[currInstructionsBlock] = append(ts.Instructions[currInstructionsBlock], *inst)
		}
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

func (ts Timestamp) String() string {
	strs := make([]string, 0, 100)
	strs = append(strs, fmt.Sprintf("file digest: %x", ts.Digest))
	strs = append(strs, fmt.Sprintf("hashed with: sha256"))
	strs = append(strs, "sets:")
	for _, set := range ts.Instructions {
		strs = append(strs, "~> instruction set")
		for _, inst := range set {
			line := "  "
			if inst.Operation != nil {
				line += inst.Operation.Name
				if inst.Operation.Binary {
					line += " " + hex.EncodeToString(inst.Argument)
				}
			} else if inst.Attestation != nil {
				line += inst.Attestation.String()
			} else {
				panic(fmt.Sprintf("invalid instruction timestamp: %v", inst))
			}
			strs = append(strs, line)
		}
	}
	return strings.Join(strs, "\n")
}

func (ts Timestamp) SerializeToFile() []byte {
	data := make([]byte, 0, 5050)
	data = append(data, headerMagic...)
	data = appendVarUint(data, 1)
	data = append(data, 0x08) // sha256
	data = append(data, ts.Digest...)
	data = append(data, ts.Serialize()...)
	return data
}

func (ts Timestamp) Serialize() []byte {
	data := make([]byte, 0, 5000)
	for i, set := range ts.Instructions {
		for _, inst := range set {
			if inst.Operation != nil {
				// write normal operation
				data = append(data, inst.Operation.Tag)
				if inst.Operation.Binary {
					data = appendVarBytes(data, inst.Argument)
				}
			} else if inst.Attestation != nil {
				// write attestation record
				data = append(data, 0x00)
				{
					// will use a new buffer for the actual attestation data
					abuf := make([]byte, 0, 100)
					if inst.BitcoinBlockHeight != 0 {
						data = append(data, bitcoinMagic...) // this goes in the main data buffer
						abuf = appendVarUint(abuf, inst.BitcoinBlockHeight)
					} else if inst.CalendarServerURL != "" {
						data = append(data, pendingMagic...) // this goes in the main data buffer
						abuf = appendVarBytes(abuf, []byte(inst.CalendarServerURL))
					} else {
						panic(fmt.Sprintf("invalid attestation: %v", inst))
					}
					data = appendVarBytes(data, abuf) // we append that data as varbytes
				}
			} else {
				panic(fmt.Sprintf("invalid instruction: %v", inst))
			}
		}
		if i+1 < len(ts.Instructions) {
			// write separator and start a new set of instructions
			data = append(data, 0xff)
		}
	}
	return data
}
