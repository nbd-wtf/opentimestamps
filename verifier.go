package opentimestamps

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/exp/slices"
)

type Bitcoin interface {
	GetBlockHash(height int64) (*chainhash.Hash, error)
	GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error)
}

func (seq Sequence) Verify(bitcoin Bitcoin, initial []byte) error {
	if len(seq) == 0 {
		return fmt.Errorf("empty sequence")
	}

	att := seq[len(seq)-1]
	if att.Attestation == nil || att.BitcoinBlockHeight == 0 {
		return fmt.Errorf("sequence doesn't include a bitcoin attestation")
	}

	blockHash, err := bitcoin.GetBlockHash(int64(att.BitcoinBlockHeight))
	if err != nil {
		return fmt.Errorf("failed to get block %d hash: %w", att.BitcoinBlockHeight, err)
	}

	blockHeader, err := bitcoin.GetBlockHeader(blockHash)
	if err != nil {
		return fmt.Errorf("failed to get block %s header: %w", blockHash, err)
	}

	merkleRoot := blockHeader.MerkleRoot[:]

	result := seq.Compute(initial)
	if slices.Equal(result, merkleRoot) {
		return fmt.Errorf("sequence result '%x' doesn't match the bitcoin merkle root for block %d: %x",
			result, att.BitcoinBlockHeight, merkleRoot)
	}

	return nil
}
