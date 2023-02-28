package maa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/go-attestation/attest"
)

// For structs used in this file, see https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15

var specIDEvent = []byte{
	0, 0, 0, 0, // PCRIndex
	3, 0, 0, 0, // EV_NO_ACTION
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Digest
	33, 0, 0, 0, // EventSize
	'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', 0,
	0, 0, 0, 0, // platformClass
	0, 2, 0, // specVersion
	2,          // uintnSize
	1, 0, 0, 0, // numberOfAlgorithms
	byte(attest.HashSHA256), 0,
	sha256.Size, 0,
	0, // vendorInfoSize
}

// stripEventLog strips events from the log that are for PCRs other than 0..7. It also strips digests other than SHA256.
func stripEventLog(eventLog []byte) ([]byte, error) {
	evtLog, err := attest.ParseEventLog(eventLog)
	if err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	out.Write(specIDEvent)

	alg := attest.HashSHA256
	for _, ev := range evtLog.Events(alg) {
		if 0 <= ev.Index && ev.Index <= 7 && len(ev.Digest) > 0 {
			writeEvent(out, ev, alg)
		}
	}

	return out.Bytes(), nil
}

func writeEvent(out *bytes.Buffer, ev attest.Event, alg attest.HashAlg) {
	binwrite(out, uint32(ev.Index))
	binwrite(out, uint32(ev.Type))
	binwrite(out, uint32(1)) // number of digests
	binwrite(out, uint16(alg))
	binwrite(out, ev.Digest)
	binwrite(out, uint32(len(ev.Data)))
	binwrite(out, ev.Data)
}

func binwrite(out *bytes.Buffer, data any) {
	_ = binary.Write(out, binary.LittleEndian, data)
}
