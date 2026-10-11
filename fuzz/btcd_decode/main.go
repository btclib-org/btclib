// Command btcd_decode decodes files with btcd's wire package and prints,
// per file, whether btcd accepted them and the bytes it writes back.
//
// fuzz/btcd_oracle.py is its only caller and holds the other half of the
// comparison. Input is one JSON object per line on stdin,
//
//	{"kind": "tx", "path": "fuzz/corpus/fuzz_tx/segwit.bin"}
//
// and so is the answer on stdout,
//
//	{"kind": "tx", "path": "...", "status": "accepted", "hex": "0200..."}
//
// status is one of:
//
//	accepted     decoded, with every octet consumed; hex is the
//	             re-serialization
//	refused      btcd returned an error, or octets were left over; error
//	             says which
//	unsupported  btcd has no decoder for this kind or command; the
//	             comparison does not count it
//	panic        btcd panicked; error holds the value
//
// A version message may end before its relay flag, and the flag then reads
// as true: Bitcoin Core initializes fRelay to true and reads it only when
// octets remain (ProcessMessage, src/net_processing.cpp). btcd always
// writes the flag. A re-serialization that is the input plus a true flag
// is reported as the input, so that the comparison is modulo that field.
//
// Octets left over after a decode are a refusal, as in btclib, where an
// object is the whole of its octets. btcd's own Deserialize does not check.
//
// Every message is decoded at the latest protocol version btcd supports,
// with witness encoding: the encoding a current peer speaks.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	pver = wire.ProtocolVersion
	enc  = wire.WitnessEncoding
	// Bitcoin Core's MAX_SIZE, the bound btclib's var_int applies.
	maxVarBytes = 0x02000000
)

type request struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type response struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Hex    string `json:"hex,omitempty"`
}

// messages maps a kind to the btcd type that decodes it. Each constructor
// returns a fresh value, so that nothing is carried from one file to the
// next.
var messages = map[string]func() wire.Message{
	"tx":          func() wire.Message { return &wire.MsgTx{} },
	"block":       func() wire.Message { return &wire.MsgBlock{} },
	"merkleblock": func() wire.Message { return &wire.MsgMerkleBlock{} },
	"addr":        func() wire.Message { return &wire.MsgAddr{} },
	"addrv2":      func() wire.Message { return &wire.MsgAddrV2{} },
	"sendaddrv2":  func() wire.Message { return &wire.MsgSendAddrV2{} },
	"version":     func() wire.Message { return &wire.MsgVersion{} },
	"verack":      func() wire.Message { return &wire.MsgVerAck{} },
	"inv":         func() wire.Message { return &wire.MsgInv{} },
	"getdata":     func() wire.Message { return &wire.MsgGetData{} },
	"notfound":    func() wire.Message { return &wire.MsgNotFound{} },
	"getblocks":   func() wire.Message { return &wire.MsgGetBlocks{} },
	"getheaders":  func() wire.Message { return &wire.MsgGetHeaders{} },
	"headers":     func() wire.Message { return &wire.MsgHeaders{} },
	"ping":        func() wire.Message { return &wire.MsgPing{} },
	"pong":        func() wire.Message { return &wire.MsgPong{} },
	"getaddr":     func() wire.Message { return &wire.MsgGetAddr{} },
	"mempool":     func() wire.Message { return &wire.MsgMemPool{} },
	"sendheaders": func() wire.Message { return &wire.MsgSendHeaders{} },
	"wtxidrelay":  func() wire.Message { return &wire.MsgWTxIdRelay{} },
	"feefilter":   func() wire.Message { return &wire.MsgFeeFilter{} },
	"reject":      func() wire.Message { return &wire.MsgReject{} },
	"getcfilters": func() wire.Message { return &wire.MsgGetCFilters{} },
	"getcfheaders": func() wire.Message {
		return &wire.MsgGetCFHeaders{}
	},
	"getcfcheckpt": func() wire.Message {
		return &wire.MsgGetCFCheckpt{}
	},
	"cfilter":    func() wire.Message { return &wire.MsgCFilter{} },
	"cfheaders":  func() wire.Message { return &wire.MsgCFHeaders{} },
	"cfcheckpt":  func() wire.Message { return &wire.MsgCFCheckpt{} },
	"filteradd":  func() wire.Message { return &wire.MsgFilterAdd{} },
	"filterload": func() wire.Message { return &wire.MsgFilterLoad{} },
}

func refused(format string, args ...any) response {
	return response{Status: "refused", Error: fmt.Sprintf(format, args...)}
}

func accepted(out []byte) response {
	return response{Status: "accepted", Hex: hex.EncodeToString(out)}
}

// payload decodes data as the payload of one message type.
func payload(newMsg func() wire.Message, data []byte) response {
	msg := newMsg()
	// MsgVersion.BtcDecode wants a *bytes.Buffer.
	r := bytes.NewBuffer(data)
	if err := msg.BtcDecode(r, pver, enc); err != nil {
		return refused("%v", err)
	}
	if r.Len() > 0 {
		return refused("%d trailing octets", r.Len())
	}
	var w bytes.Buffer
	if err := msg.BtcEncode(&w, pver, enc); err != nil {
		return refused("re-encoding: %v", err)
	}
	return accepted(omitRelay(msg, data, w.Bytes()))
}

// omitRelay returns the input in place of its re-serialization when the two
// differ only by the true relay flag of a version message the input left
// out.
func omitRelay(msg wire.Message, in, out []byte) []byte {
	if _, ok := msg.(*wire.MsgVersion); ok && len(out) == len(in)+1 &&
		bytes.Equal(out[:len(in)], in) && out[len(in)] == 1 {
		return in
	}
	return out
}

// message decodes data as one whole p2p message, envelope included. The
// network is read off the first four octets, because the question is
// whether the rest is a message, not whose.
func message(data []byte) response {
	if len(data) < 4 {
		return refused("shorter than a magic")
	}
	net := wire.BitcoinNet(binary.LittleEndian.Uint32(data))
	r := bytes.NewReader(data)
	_, msg, in, err := wire.ReadMessageWithEncodingN(r, pver, net, enc)
	if errors.Is(err, wire.ErrUnknownMessage) {
		return response{Status: "unsupported", Error: err.Error()}
	}
	if err != nil {
		return refused("%v", err)
	}
	if r.Len() > 0 {
		return refused("%d trailing octets", r.Len())
	}
	var w bytes.Buffer
	if _, err := wire.WriteMessageWithEncodingN(&w, msg, pver, net, enc); err != nil {
		return refused("re-encoding: %v", err)
	}
	out := w.Bytes()
	if _, ok := msg.(*wire.MsgVersion); ok {
		// the payload follows the 24 octet header; the length and the
		// checksum are rewritten around the payload omitRelay returns
		body := omitRelay(msg, in, out[wire.MessageHeaderSize:])
		header := append([]byte{}, out[:wire.MessageHeaderSize]...)
		binary.LittleEndian.PutUint32(header[16:], uint32(len(body)))
		copy(header[20:], chainhash.DoubleHashB(body)[:4])
		out = append(header, body...)
	}
	return accepted(out)
}

func varInt(data []byte) response {
	r := bytes.NewReader(data)
	n, err := wire.ReadVarInt(r, pver)
	if err != nil {
		return refused("%v", err)
	}
	if r.Len() > 0 {
		return refused("%d trailing octets", r.Len())
	}
	var w bytes.Buffer
	if err := wire.WriteVarInt(&w, pver, n); err != nil {
		return refused("re-encoding: %v", err)
	}
	return accepted(w.Bytes())
}

func varBytes(data []byte) response {
	r := bytes.NewReader(data)
	b, err := wire.ReadVarBytes(r, pver, maxVarBytes, "var_bytes")
	if err != nil {
		return refused("%v", err)
	}
	if r.Len() > 0 {
		return refused("%d trailing octets", r.Len())
	}
	var w bytes.Buffer
	if err := wire.WriteVarBytes(&w, pver, b); err != nil {
		return refused("re-encoding: %v", err)
	}
	return accepted(w.Bytes())
}

func decode(req request) (res response) {
	defer func() {
		if p := recover(); p != nil {
			res = response{Status: "panic", Error: fmt.Sprint(p)}
		}
		res.Kind, res.Path = req.Kind, req.Path
	}()

	data, err := os.ReadFile(req.Path)
	if err != nil {
		return refused("%v", err)
	}
	switch newMsg, ok := messages[req.Kind]; {
	case ok:
		return payload(newMsg, data)
	case req.Kind == "message":
		return message(data)
	case req.Kind == "var_int":
		return varInt(data)
	case req.Kind == "var_bytes":
		return varBytes(data)
	}
	return response{Status: "unsupported", Error: "no btcd decoder for " + req.Kind}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var req request
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			fmt.Fprintln(os.Stderr, "bad request:", err)
			os.Exit(2)
		}
		if err := out.Encode(decode(req)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := in.Err(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
