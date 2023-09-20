package opentimestamps

import "github.com/btcsuite/btcd/rpcclient"

func NewBitcoindInterface(config rpcclient.ConnConfig) (Bitcoin, error) {
	return rpcclient.New(&config, nil)
}
