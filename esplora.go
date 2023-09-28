package opentimestamps

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/exp/slices"
)

func NewEsploraClient(url string) Bitcoin {
	if strings.HasSuffix(url, "/") {
		url = url[0 : len(url)-1]
	}
	return esplora{url}
}

type esplora struct{ baseurl string }

func (e esplora) GetBlockHash(height int64) (*chainhash.Hash, error) {
	resp, err := http.Get(e.baseurl + "/block-height/" + strconv.FormatInt(height, 10))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	hexb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	hash, err := hex.DecodeString(string(hexb))
	if err != nil {
		return nil, err
	}
	if len(hash) != chainhash.HashSize {
		return nil, fmt.Errorf("got block hash (%x) of invalid size (expected %d)", hash, chainhash.HashSize)
	}

	slices.Reverse(hash)
	var chash chainhash.Hash
	copy(chash[:], hash)
	return &chash, nil
}

func (e esplora) GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error) {
	resp, err := http.Get(fmt.Sprintf("%s/block/%s/header", e.baseurl, hash.String()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	hexb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headerHash, err := hex.DecodeString(string(hexb))
	if err != nil {
		return nil, err
	}

	header := &wire.BlockHeader{}
	if err := header.BtcDecode(bytes.NewBuffer(headerHash), 0, 0); err != nil {
		return nil, err
	}

	return header, nil
}
