package opentimestamps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	0xf0: {"append", 0xf0, true, func(curr []byte, arg []byte) []byte {
		result := make([]byte, len(curr)+len(arg))
		copy(result[0:], curr)
		copy(result[len(curr):], arg)
		return result
	}},
	0xf1: {"prepend", 0xf1, true, func(curr []byte, arg []byte) []byte {
		result := make([]byte, len(curr)+len(arg))
		copy(result[0:], arg)
		copy(result[len(arg):], curr)
		return result
	}},
	0xf2: {"reverse", 0xf2, false, func(curr []byte, arg []byte) []byte { panic("reverse not implemented") }},
	0xf3: {"hexlify", 0xf3, false, func(curr []byte, arg []byte) []byte { panic("hexlify not implemented") }},
	0x02: {"sha1", 0x02, false, func(curr []byte, arg []byte) []byte { panic("sha1 not implemented") }},
	0x03: {"ripemd160", 0x03, false, ripemd160},
	0x08: {"sha256", 0x08, false, func(curr []byte, arg []byte) []byte {
		v := sha256.Sum256(curr)
		return v[:]
	}},
	0x67: {"keccak256", 0x67, false, func(curr []byte, arg []byte) []byte { panic("keccak256 not implemented") }},
}

// A File represents the parsed content of an .ots file: it has an initial digest and
// a series of sequences of instructions. Each sequence must be evaluated separately, applying the operations
// on top of each other, starting with the .Digest until they end on an attestation.
type File struct {
	Digest       []byte
	Instructions []Sequence
}

// a Instruction can be an operation like "append" or "prepend" (this will be the case when .Operation != nil)
// or an attestation (when .Attestation != nil).
// It will have a non-nil .Argument whenever the operation requires an argument.
type Instruction struct {
	*Operation
	Argument []byte
	*Attestation
}

type Sequence []Instruction

func (seq Sequence) Compute(initial []byte) []byte {
	current := initial
	for _, inst := range seq {
		if inst.Operation == nil {
			break
		}
		current = inst.Operation.Apply(current, inst.Argument)
	}
	return current
}

func (ts File) GetPendingSequences() []Sequence {
	bitcoin := ts.GetBitcoinAttestedSequences()

	results := make([]Sequence, 0, len(ts.Instructions))
	for _, seq := range ts.Instructions {
		if len(seq) > 0 && seq[len(seq)-1].Attestation != nil && seq[len(seq)-1].Attestation.CalendarServerURL != "" {
			// this is a calendar sequence, fine
			// now we check if this same sequence isn't contained in a bigger one that contains a bitcoin attestation
			cseq := seq
			for _, bseq := range bitcoin {
				if len(bseq) < len(cseq) {
					continue
				}

				if slices.EqualFunc(bseq[0:len(cseq)], cseq, func(a, b Instruction) bool { return CompareInstructions(a, b) == 0 }) {
					goto thisSequenceIsAlreadyConfirmed
				}
			}

			// sequence not confirmed, so add it to pending result
			results = append(results, seq)

		thisSequenceIsAlreadyConfirmed:
			// skip this
			continue
		}
	}
	return results
}

func (ts File) GetBitcoinAttestedSequences() []Sequence {
	results := make([]Sequence, 0, len(ts.Instructions))
	for _, seq := range ts.Instructions {
		if len(seq) > 0 && seq[len(seq)-1].Attestation != nil && seq[len(seq)-1].Attestation.BitcoinBlockHeight > 0 {
			results = append(results, seq)
		}
	}
	return results
}

func (ts File) Human() string {
	strs := make([]string, 0, 100)
	strs = append(strs, fmt.Sprintf("file digest: %x", ts.Digest))
	strs = append(strs, fmt.Sprintf("hashed with: sha256"))
	strs = append(strs, "instruction sequences:")
	for _, seq := range ts.Instructions {
		strs = append(strs, "~>")
		for _, inst := range seq {
			line := "  "
			if inst.Operation != nil {
				line += inst.Operation.Name
				if inst.Operation.Binary {
					line += " " + hex.EncodeToString(inst.Argument)
				}
			} else if inst.Attestation != nil {
				line += inst.Attestation.Human()
			} else {
				panic(fmt.Sprintf("invalid instruction timestamp: %v", inst))
			}
			strs = append(strs, line)
		}
	}
	return strings.Join(strs, "\n")
}

func (ts File) SerializeToFile() []byte {
	data := make([]byte, 0, 5050)
	data = append(data, headerMagic...)
	data = appendVarUint(data, 1)
	data = append(data, 0x08) // sha256
	data = append(data, ts.Digest...)
	data = append(data, ts.SerializeInstructionSequences()...)
	return data
}

func (ts File) SerializeInstructionSequences() []byte {
	sequences := make([]Sequence, len(ts.Instructions))
	copy(sequences, ts.Instructions)

	// first we sort everything so the checkpoint stuff makes sense
	slices.SortFunc(sequences, func(a, b Sequence) int { return slices.CompareFunc(a, b, CompareInstructions) })

	// checkpoints we may leave to the next people
	sequenceCheckpoints := make([][]int, len(sequences))
	for s1 := range sequences {
		// keep an ordered slice of all the checkpoints we will potentially leave during our write journey for this sequence
		checkpoints := make([]int, 0, len(sequences[s1]))
		for s2 := s1 + 1; s2 < len(sequences); s2++ {
			chp := getCommonPrefixIndex(sequences[s1], sequences[s2])
			if pos, found := slices.BinarySearch(checkpoints, chp); !found {
				checkpoints = append(checkpoints, -1)        // make room
				copy(checkpoints[pos+1:], checkpoints[pos:]) // move elements to the right
				checkpoints[pos] = chp                       // insert this
			}
		}
		sequenceCheckpoints[s1] = checkpoints
	}

	// now actually go through the sequences writing them
	result := make([]byte, 0, 500)
	for s, seq := range sequences {
		startingAt := 0
		if s > 0 {
			// we will always start at the last checkpoint left by the previous sequence
			startingAt = sequenceCheckpoints[s-1][len(sequenceCheckpoints[s-1])-1]
		}

		for i := startingAt; i < len(seq); i++ {
			// before writing anything, decide if we wanna leave a checkpoint here
			for _, chk := range sequenceCheckpoints[s] {
				if chk == i {
					// leave a checkpoint
					result = append(result, 0xff)
				}
			}

			inst := seq[i]
			if inst.Operation != nil {
				// write normal operation
				result = append(result, inst.Operation.Tag)
				if inst.Operation.Binary {
					result = appendVarBytes(result, inst.Argument)
				}
			} else if inst.Attestation != nil {
				// write attestation record
				result = append(result, 0x00)
				{
					// will use a new buffer for the actual attestation result
					abuf := make([]byte, 0, 100)
					if inst.BitcoinBlockHeight != 0 {
						result = append(result, bitcoinMagic...) // this goes in the main result buffer
						abuf = appendVarUint(abuf, inst.BitcoinBlockHeight)
					} else if inst.CalendarServerURL != "" {
						result = append(result, pendingMagic...) // this goes in the main result buffer
						abuf = appendVarBytes(abuf, []byte(inst.CalendarServerURL))
					} else {
						panic(fmt.Sprintf("invalid attestation: %v", inst))
					}
					result = appendVarBytes(result, abuf) // we append that result as varbytes
				}
			} else {
				panic(fmt.Sprintf("invalid instruction: %v", inst))
			}
		}
	}
	return result
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

func (att Attestation) Human() string {
	if att.BitcoinBlockHeight != 0 {
		return fmt.Sprintf("bitcoin(%d)", att.BitcoinBlockHeight)
	} else if att.CalendarServerURL != "" {
		return fmt.Sprintf("pending(%s)", att.CalendarServerURL)
	} else {
		return "unknown/broken"
	}
}
