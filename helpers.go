package opentimestamps

import (
	"strings"

	"golang.org/x/exp/slices"
)

// CompareInstructions returns negative if a<b, 0 if a=b and positive if a>b.
// It considers an operation smaller than an attestation, a pending attestation smaller than a Bitcoin attestation.
// It orders operations by their tag byte and then by their argument.
func CompareInstructions(a, b Instruction) int {
	if a.Operation != nil {
		if b.Attestation != nil {
			// a is an operation but b is an attestation, a is bigger
			return +1
		}
		if a.Operation == b.Operation {
			// if both are the same operation sort by the argument
			return slices.Compare(a.Argument, b.Argument)
		}

		// sort by the operation
		if a.Operation.Tag < b.Operation.Tag {
			return -1
		} else if a.Operation.Tag > b.Operation.Tag {
			return 1
		} else {
			return 0
		}
	} else if a.Attestation != nil && b.Attestation == nil {
		// a is an attestation but b is not, b is bigger
		return -1
	} else if a.Attestation != nil && b.Attestation != nil {
		// both are attestations
		if a.Attestation.BitcoinBlockHeight == 0 && b.Attestation.BitcoinBlockHeight == 0 {
			// none are bitcoin attestations
			return strings.Compare(a.Attestation.CalendarServerURL, b.Attestation.CalendarServerURL)
		}
		if a.Attestation.BitcoinBlockHeight != 0 && b.Attestation.BitcoinBlockHeight != 0 {
			// both are bitcoin attestations
			return int(b.Attestation.BitcoinBlockHeight - a.Attestation.BitcoinBlockHeight)
		}

		// one is bitcoin and the other is not -- compare by bitcoin block,
		// but reverse the result since the one with 0 should not be considered bigger
		return -1 * int(b.Attestation.BitcoinBlockHeight-a.Attestation.BitcoinBlockHeight)
	} else {
		// this shouldn't happen
		return 0
	}
}
