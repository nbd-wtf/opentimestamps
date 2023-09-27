package opentimestamps

import (
	"fmt"
	"io"

	"golang.org/x/exp/slices"
)

func parseCalendarServerResponse(buf Buffer) (Sequence, error) {
	seqs, err := parseTimestamp(buf)
	if err != nil {
		return nil, err
	}
	if len(seqs) != 1 {
		return nil, fmt.Errorf("invalid number of sequences obtained: %d", len(seqs))
	}

	return seqs[0], nil
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

	if seqs, err := parseTimestamp(buf); err != nil {
		return nil, err
	} else {
		ts.Instructions = seqs
	}

	return ts, nil
}

func parseTimestamp(buf Buffer) ([]Sequence, error) {
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
	seqs := make([]Sequence, 0, 10)

	// we will store checkpoints here
	checkpoints := make([][]Instruction, 0, 4)

	// start first instruction block
	seqs = append(seqs, make([]Instruction, 0, 30))

	// go read these tags
	for {
		tag, err := buf.readByte()
		if err != nil {
			if err == io.EOF {
				return seqs, nil
			}
			return nil, fmt.Errorf("failed to read operation byte: %w", err)
		}

		if tag == 0x00 {
			// enter an attestation context
			magic, err := buf.readBytes(8)
			if err != nil {
				return nil, fmt.Errorf("failed to read attestion magic bytes: %w", err)
			}

			this, err := buf.readVarBytes()
			if err != nil {
				return nil, fmt.Errorf("failed to read attestation bytes: %w", err)
			}
			abuf := NewBuffer(this)

			switch {
			case slices.Equal(magic, pendingMagic):
				val, err := abuf.readVarBytes()
				if err != nil {
					return nil, fmt.Errorf("failed reading calendar server url: %w", err)
				}
				seqs[currInstructionsBlock] = append(
					seqs[currInstructionsBlock],
					Instruction{Attestation: &Attestation{CalendarServerURL: string(val)}},
				)
			case slices.Equal(magic, bitcoinMagic):
				val, err := abuf.readVarUint()
				if err != nil {
					return nil, fmt.Errorf("failed reading bitcoin block number: %w", err)
				}
				seqs[currInstructionsBlock] = append(
					seqs[currInstructionsBlock],
					Instruction{Attestation: &Attestation{BitcoinBlockHeight: val}},
				)
			default:
				return nil, fmt.Errorf("unsupported attestation type '%x': %x", magic, this)
			}

			// check if we have checkpoints and, if yes, copy them in a new block of instructions
			ncheckpoints := len(checkpoints)
			if ncheckpoints > 0 {
				// use this checkpoint as the starting point for the next block
				cp := checkpoints[ncheckpoints-1]
				checkpoints = checkpoints[0 : ncheckpoints-1] // remove this from the stack
				seqs = append(seqs, cp)
				currInstructionsBlock++
			}
		} else if tag == 0xff {
			// pick up a checkpoint to be used later
			currentBlock := seqs[currInstructionsBlock]
			cp := make([]Instruction, len(currentBlock))
			copy(cp, currentBlock)
			checkpoints = append(checkpoints, cp)
		} else {
			// a new operation in this block
			inst, err := readInstruction(buf, tag)
			if err != nil {
				return nil, fmt.Errorf("failed to read instruction: %w", err)
			}
			seqs[currInstructionsBlock] = append(seqs[currInstructionsBlock], *inst)
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
