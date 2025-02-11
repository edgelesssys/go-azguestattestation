package maa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	ptpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	indexHCLReport = 0x1400001
	indexAKPub     = 0x81000003
	indexAKCert    = 0x1C101D0
)

type (
	Attestation = attest.Attestation
	Quote       = ptpm.Quote
)

// pcrSelection is the minimal set of PCRs required by MAA as used in the official sample.
//
// Previously, we used the full selection, but that triggered a bug in MAA after an update. The
// actual selection doesn't really matter because the purpose of this library is to use the MAA
// to verify that the SNP report comes from an Azure CVM. The PCRs should be verified separately.
var pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}

func getSignatureRSA(rawSig []byte) ([]byte, error) {
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(rawSig))
	if err != nil {
		return nil, err
	}
	return sig.RSA.Signature, nil
}

func tpmMarshal(data []byte) ([]byte, error) {
	tpmBytes := tpmutil.U16Bytes(data)
	buf := bytes.Buffer{}
	if err := tpmBytes.TPMMarshal(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getSHA256QuoteIndex(quotes []*Quote) (int, error) {
	for idx, quote := range quotes {
		if quote.GetPcrs().GetHash() == ptpm.HashAlgo_SHA256 {
			return idx, nil
		}
	}
	return 0, errors.New("attestation did not include SHA256 hashed PCRs")
}

type tpm struct {
	t io.ReadWriteCloser
}

func newTPM(tpmHandle io.ReadWriter) (*tpm, error) {
	if tpmHandle != nil {
		return &tpm{nopCloser{tpmHandle}}, nil
	}
	t, err := tpm2.OpenTPM()
	if err != nil {
		return nil, err
	}
	return &tpm{t}, nil
}

func (t *tpm) Close() error {
	return t.t.Close()
}

func (t *tpm) getHCLReport() ([]byte, error) {
	return tpm2.NVReadEx(t.t, indexHCLReport, tpm2.HandleOwner, "", 0)
}

func (t *tpm) attest(nonce []byte) (*Attestation, error) {
	cert, err := tpm2.NVReadEx(t.t, indexAKCert, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("reading AK certificate from NV index: %w", err)
	}
	key, err := client.LoadCachedKey(t.t, indexAKPub, client.NullSession{})
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer key.Close()
	attestation, err := key.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("generating attestation: %w", err)
	}

	// replace quote over all PCRs with quote over the selection
	quote, err := key.Quote(pcrSelection, nonce)
	if err != nil {
		return nil, fmt.Errorf("generating quote: %w", err)
	}
	attestation.Quotes = []*ptpm.Quote{quote}

	attestation.AkCert = cert
	return attestation, nil
}

// getEncryptionKey gets an encryption key bound to the PCR state in quotes.
func (t *tpm) getEncryptionKey(quotes []*Quote) (pubKey, certInfo, certInfoSig []byte, err error) {
	quoteIdx, err := getSHA256QuoteIndex(quotes)
	if err != nil {
		return nil, nil, nil, err
	}
	pcrDigest, sel, err := getSHA256PCRDigest(quotes[quoteIdx].Pcrs.Pcrs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting PCR digest: %w", err)
	}

	template, err := t.getEncryptionKeyTemplate(pcrDigest, sel)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting key template: %w", err)
	}

	handle, pubKey, _, _, _, _, err := tpm2.CreatePrimaryEx(t.t, tpm2.HandleNull, sel, "", "", template)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating key: %w", err)
	}
	defer t.flushContext(handle)

	certifyInfo, signature, err := tpm2.Certify(t.t, "", "", handle, indexAKPub, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certifying key: %w", err)
	}

	pubKey, err = tpmMarshal(pubKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshaling key: %w", err)
	}

	// signature is TPMT_SIGNATURE, MAA wants TPM2B_PUBLIC_KEY_RSA.buffer, which starts at offset 6
	return pubKey, certifyInfo, signature[6:], nil
}

// getEncryptionPubKey gets an encryption key bound to the current PCR state.
func (t *tpm) getEncryptionPubKey() (crypto.PublicKey, error) {
	pcrs, err := t.readPCRs()
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}
	pcrDigest, sel, err := getSHA256PCRDigest(pcrs.Pcrs)
	if err != nil {
		return nil, fmt.Errorf("getting PCR digest: %w", err)
	}

	template, err := t.getEncryptionKeyTemplate(pcrDigest, sel)
	if err != nil {
		return nil, fmt.Errorf("getting key template: %w", err)
	}

	handle, pubKey, err := tpm2.CreatePrimary(t.t, tpm2.HandleNull, sel, "", "", template)
	if err != nil {
		return nil, fmt.Errorf("creating key: %w", err)
	}
	t.flushContext(handle)

	return pubKey, nil
}

func (t *tpm) decrypt(ciphertext []byte) ([]byte, error) {
	pcrs, err := t.readPCRs()
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}
	pcrDigest, sel, err := getSHA256PCRDigest(pcrs.Pcrs)
	if err != nil {
		return nil, fmt.Errorf("getting PCR digest: %w", err)
	}

	template, err := t.getEncryptionKeyTemplate(pcrDigest, sel)
	if err != nil {
		return nil, fmt.Errorf("getting key template: %w", err)
	}

	handle, _, err := tpm2.CreatePrimary(t.t, tpm2.HandleNull, sel, "", "", template)
	if err != nil {
		return nil, fmt.Errorf("creating key: %w", err)
	}
	defer t.flushContext(handle)

	session, _, err := tpm2.StartAuthSession(t.t, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 32), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("starting session: %w", err)
	}
	defer t.flushContext(session)
	if err := tpm2.PolicyPCR(t.t, session, pcrDigest, sel); err != nil {
		return nil, fmt.Errorf("setting PCR policy: %w", err)
	}

	plaintext, err := tpm2.RSADecryptWithSession(t.t, session, handle, "", ciphertext, &tpm2.AsymScheme{Alg: tpm2.AlgRSAES}, "")
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

func (t *tpm) flushContext(handle tpmutil.Handle) {
	_ = tpm2.FlushContext(t.t, handle)
}

func (t *tpm) readPCRs() (*ptpm.PCRs, error) {
	return client.ReadPCRs(t.t, pcrSelection)
}

func (t *tpm) getEncryptionKeyTemplate(pcrDigest []byte, sel tpm2.PCRSelection) (tpm2.Public, error) {
	session, _, err := tpm2.StartAuthSession(t.t, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 32), nil, tpm2.SessionTrial, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return tpm2.Public{}, fmt.Errorf("starting session: %w", err)
	}
	defer t.flushContext(session)
	if err := tpm2.PolicyPCR(t.t, session, pcrDigest, sel); err != nil {
		return tpm2.Public{}, fmt.Errorf("setting PCR policy: %w", err)
	}
	policyDigest, err := tpm2.PolicyGetDigest(t.t, session)
	if err != nil {
		return tpm2.Public{}, fmt.Errorf("getting policy digest: %w", err)
	}
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagNoDA,
		AuthPolicy: policyDigest,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: 2048,
		},
	}, nil
}

func getSHA256PCRDigest(pcrs map[uint32][]byte) ([]byte, tpm2.PCRSelection, error) {
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256}
	for k := range pcrs {
		sel.PCRs = append(sel.PCRs, int(k))
	}
	sort.Ints(sel.PCRs)
	hasher := sha256.New()
	for _, k := range sel.PCRs {
		if _, err := hasher.Write(pcrs[uint32(k)]); err != nil {
			return nil, tpm2.PCRSelection{}, err
		}
	}
	return hasher.Sum(nil), sel, nil
}

type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error {
	return nil
}
