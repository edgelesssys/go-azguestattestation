package maa

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripEventLog(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// initial specIDEvent
	out := bytes.NewBuffer([]byte{
		0, 0, 0, 0, // PCRIndex
		3, 0, 0, 0, // EV_NO_ACTION
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Digest
		37, 0, 0, 0, // EventSize
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0, 0, 0, 0, // platformClass
		0, 2, 0, // specVersion
		2,          // uintnSize
		2, 0, 0, 0, // numberOfAlgorithms
		byte(attest.HashSHA1), 0,
		sha1.Size, 0,
		byte(attest.HashSHA256), 0,
		sha256.Size, 0,
		0, // vendorInfoSize
	})

	writeEvent(out, attest.Event{Index: 0, Type: 1, Data: []byte{2, 3}, Digest: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, attest.HashSHA256)
	writeEvent(out, attest.Event{Index: 8, Type: 1, Data: []byte{2, 3}, Digest: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, attest.HashSHA256)
	writeEvent(out, attest.Event{Index: 0, Type: 1, Data: []byte{2, 3}, Digest: []byte("AAAAAAAAAAAAAAAAAAAA")}, attest.HashSHA1)
	writeEvent(out, attest.Event{Index: 7, Type: 2, Data: []byte{3, 4}, Digest: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")}, attest.HashSHA256)

	stripped, err := stripEventLog(out.Bytes())
	require.NoError(err)
	evtLog, err := attest.ParseEventLog(stripped)
	require.NoError(err)

	assert.Equal([]attest.Event{
		{Index: 0, Type: 1, Data: []byte{2, 3}, Digest: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		{Index: 7, Type: 2, Data: []byte{3, 4}, Digest: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")},
	}, evtLog.Events(attest.HashSHA256))

	assert.Equal([]attest.Event{
		{Index: 0, Type: 1, Data: []byte{2, 3}, Digest: nil},
		{Index: 7, Type: 2, Data: []byte{3, 4}, Digest: nil},
	}, evtLog.Events(attest.HashSHA1))
}
