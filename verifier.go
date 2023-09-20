package opentimestamps

import (
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Bitcoin interface {
	GetBlockHash(height int64) (*chainhash.Hash, error)
	GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error)
}

// VerifyAttestation checks a BitcoinAttestation using a given hash digest. It
// returns the time of the block if the verification succeeds, an error
// otherwise.
func VerifyAttestation(bitcoinInterface Bitcoin, digest []byte, a *BitcoinAttestation) (*time.Time, error) {
	if a.Height > math.MaxInt64 {
		return nil, fmt.Errorf("illegal block height")
	}
	blockHash, err := bitcoinInterface.GetBlockHash(int64(a.Height))
	if err != nil {
		return nil, err
	}
	h, err := bitcoinInterface.GetBlockHeader(blockHash)
	if err != nil {
		return nil, err
	}

	merkleRootBytes := h.MerkleRoot[:]
	err = a.VerifyAgainstBlockHash(digest, merkleRootBytes)
	if err != nil {
		return nil, err
	}
	utc := h.Timestamp.UTC()

	return &utc, nil
}

// A BitcoinVerification is the result of verifying a BitcoinAttestation
type BitcoinVerification struct {
	Timestamp       *Timestamp
	Attestation     *BitcoinAttestation
	AttestationTime *time.Time
	Error           error
}

// BitcoinVerifications returns the all bitcoin attestation results for the
// timestamp.
func BitcoinVerifications(bitcoinInterface Bitcoin, t *Timestamp) (res []BitcoinVerification) {
	t.Walk(func(ts *Timestamp) {
		for _, att := range ts.Attestations {
			btcAtt, ok := att.(*BitcoinAttestation)
			if !ok {
				continue
			}
			attTime, err := VerifyAttestation(bitcoinInterface, ts.Message, btcAtt)
			res = append(res, BitcoinVerification{
				Timestamp:       ts,
				Attestation:     btcAtt,
				AttestationTime: attTime,
				Error:           err,
			})
		}
	})
	return res
}

// Verify returns the earliest bitcoin-attested time, or nil if none can be
// found or verified successfully.
func Verify(bitcoinInterface Bitcoin, t *Timestamp) (ret *time.Time, err error) {
	res := BitcoinVerifications(bitcoinInterface, t)
	for _, r := range res {
		if r.Error != nil {
			err = r.Error
			continue
		}
		if ret == nil || r.AttestationTime.Before(*ret) {
			ret = r.AttestationTime
		}
	}
	return
}
