# opentimestamps

Interact with calendar servers, create and verify OTS attestations.

# How to use

Full documentation at https://pkg.go.dev/github.com/nbd-wtf/opentimestamps. See some commented pseudocode below (you probably should not try to run it as it is).

```go
package main

import "github.com/nbd-wtf/opentimestamps"

func main () {
    // create a timestamp at a specific calendar server
    hash := sha256.Sum256([]byte{1,2,3,4,5,6})
    seq, _ := opentimestamps.Stamp(context.Background(), "https://alice.btc.calendar.opentimestamps.org/", hash)

    // you can just call .Upgrade() to get the upgraded sequence (or an error if not yet available)
    upgradedSeq, err := seq.Upgrade(context.Background(), hash[:])
    if err != nil {
        fmt.Println("wait more")
    }

    // a File is a struct that represents the content of an .ots file, which contains the initial digest and any number of sequences
    file := File{
        Digest: hash,
        Sequences: []Sequence{seq},
    }

    // it can be written to disk
    os.WriteFile("file.ots", file.SerializeToFile(), 0644)

    // or printed in human-readable format
    fmt.Println(file.Human())

    // sequences are always composed of a bunch of operation instructions -- these can be, for example, "append", "prepend", "sha256"
    fmt.Println(seq[0].Operation.Name) // "append"
    fmt.Println(seq[1].Operation.Name) // "sha256"
    fmt.Println(seq[2].Operation.Name) // "prepend"

    // "prepend" and "append" are "binary", i.e. they take an argument
    fmt.Println(hex.EncodeToString(seq[2].Argument)) // "c40fe258f9b828a0b5a7"

    // all these instructions can be executed in order, starting from the initial hash
    result := seq.Compute(hash) // this is the value we send to the calendar server in order to get the upgraded sequence on .Upgrade()
    finalResult := upgradedSeq.Compute(hash) // this should be the merkle root of a bitcoin block if this sequence is upgraded

    // each sequence always ends in an "attestation"
    // it can be either a pending attestation, i.e. a reference to a calendar server from which we will upgrade this sequence later
    fmt.Println(seq[len(seq)-1].Attestation.CalendarServerURL) // "https://alice.btc.calendar.opentimestamps.org/"
    // or it can be a reference to a bitcoin block, the merkle root of which we will check against the result of Compute() for verifying
    fmt.Println(upgradedSeq[len(upgradedSeq)-1].Attestation.BitcoinBlockHeight) // 810041

    // speaking of verifying, this is how we do it:
    // first we need some source of bitcoin blocks,
    var bitcoin opentimestamps.Bitcoin
    if useLocallyRunningBitcoindNode {
        // it can be either a locally running bitcoind node
        bitcoin, _ = opentimestamps.NewBitcoindInterface(rpcclient.ConnConfig{
            User:         "nakamoto",
            Pass:         "mumbojumbo",
            HTTPPostMode: true,
        })
    } else {
        // or an esplora HTTP endpoint
        bitcoin = opentimestamps.NewEsploraClient("https://blockstream.info/api")
    }

    // then we pass that to a sequence
    if err := upgradedSeq.Verify(bitcoin, hash); err == nil {
        fmt.Println("it works!")
    }
}
```

You can also take a look at [`ots`](https://github.com/fiatjaf/ots), a simple CLI to OpenTimestamps which is basically a wrapper over this library.

# License

Public Domain
