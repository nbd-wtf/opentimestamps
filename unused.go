package opentimestamps

import (
	deprecated_ripemd160 "golang.org/x/crypto/ripemd160"
)

func ripemd160(curr []byte, arg []byte) []byte {
	return deprecated_ripemd160.New().Sum(curr)
}
