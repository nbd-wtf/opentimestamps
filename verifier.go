package opentimestamps

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Bitcoin interface {
	GetBlockHash(height int64) (*chainhash.Hash, error)
	GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error)
}
