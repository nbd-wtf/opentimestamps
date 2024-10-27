package opentimestamps

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Bitcoin interface {
	GetBlockHash(height int64) (*chainhash.Hash, error)
	GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error)
}

// Verify validates sequence of operations that starts with digest and ends on a Bitcoin attestation against
// an actual Bitcoin block, as given by the provided Bitcoin interface.
func (seq Sequence) Verify(bitcoin Bitcoin, digest []byte) (*wire.MsgTx, error) {
	if len(seq) == 0 {
		return nil, fmt.Errorf("empty sequence")
	}

	att := seq[len(seq)-1]
	if att.Attestation == nil || att.BitcoinBlockHeight == 0 {
		return nil, fmt.Errorf("sequence doesn't include a bitcoin attestation")
	}

	blockHash, err := bitcoin.GetBlockHash(int64(att.BitcoinBlockHeight))
	if err != nil {
		return nil, fmt.Errorf("failed to get block %d hash: %w", att.BitcoinBlockHeight, err)
	}

	blockHeader, err := bitcoin.GetBlockHeader(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block %s header: %w", blockHash, err)
	}

	merkleRoot := blockHeader.MerkleRoot[:]
	result, tx := seq.Compute(digest)

	if !bytes.Equal(result, merkleRoot) {
		return nil, fmt.Errorf("sequence result '%x' doesn't match the bitcoin merkle root for block %d: %x",
			result, att.BitcoinBlockHeight, merkleRoot)
	}

	return tx, nil
}
