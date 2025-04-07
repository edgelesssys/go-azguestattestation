package maa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
)

var (
	// APIVersion is the version of the MAA API to use.
	APIVersion = "2020-10-01"
	// OSBuild represents the OS build string.
	OSBuild = "Edgeless"
	// OSDistro represents the OS distribution, for example Ubuntu.
	OSDistro = "Edgeless"
	// OSType represents the OS type, for example Linux.
	OSType = "Edgeless"
)

// GetEncryptedToken requests a token from MAA, which will be encrypted.
func GetEncryptedToken(ctx context.Context, params Parameters, nonce []byte, maaURL string, httpClient HttpClient) (string, error) {
	// create full URL
	if maaURL == "" {
		return "", errors.New("maaURL is empty")
	}
	maaURL, err := url.JoinPath(maaURL, "attest/AzureGuest")
	if err != nil {
		return "", fmt.Errorf("parsing maaURL: %w", err)
	}
	maaURL += fmt.Sprintf("?api-version=%s", APIVersion)

	attInfo, err := newAttestationInfo(params)
	if err != nil {
		return "", err
	}
	attInfo.ClientPayload.Nonce = nonce

	// send attestation info to MAA
	reqBytes, err := json.Marshal(attestRequest{attInfo})
	if err != nil {
		return "", fmt.Errorf("marshaling AttestationInfo: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, maaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return "", fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("doing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if msg, err := io.ReadAll(resp.Body); err == nil && len(msg) > 0 {
			return "", fmt.Errorf("MAA returned %v: %s", resp.Status, msg)
		}
		return "", fmt.Errorf("MAA returned %v", resp.Status)
	}

	var token struct{ Token string }
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return token.Token, nil
}

func marshalURLEncoded(data []byte) []byte {
	return []byte("\"" + base64.RawURLEncoding.EncodeToString(data) + "\"")
}

func unmarshalURLEncoded(data []byte) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(string(data[1 : len(data)-1]))
}

type attestRequest struct {
	AttestationInfo attestationInfo
}

type attestationInfo struct {
	AttestationProtocolVersion string
	ClientPayload              clientPayload
	IsolationInfo              isolationInfo
	OSBuild                    infoString
	OSDistro                   infoString
	OSType                     infoString
	OSVersionMajor             int
	OSVersionMinor             int
	TcgLogs                    []byte
	TpmInfo                    tpmInfo
}

// newAttestationInfo converts params into the format expected by the MAA.
func newAttestationInfo(params Parameters) (attestationInfo, error) {
	akPub, err := tpmMarshal(params.Attestation.AkPub)
	if err != nil {
		return attestationInfo{}, fmt.Errorf("marshaling AK pub: %w", err)
	}

	eventLog, err := stripEventLog(params.Attestation.EventLog)
	if err != nil {
		return attestationInfo{}, fmt.Errorf("stripping event log: %w", err)
	}

	quoteIdx, err := getSHA256QuoteIndex(params.Attestation.Quotes)
	if err != nil {
		return attestationInfo{}, err
	}
	quote := params.Attestation.Quotes[quoteIdx]

	pcrSig, err := getSignatureRSA(quote.RawSig)
	if err != nil {
		return attestationInfo{}, fmt.Errorf("parsing quote signature: %w", err)
	}

	quotePcrs := quote.Pcrs.Pcrs
	var pcrSet []int
	for k := range quotePcrs {
		pcrSet = append(pcrSet, int(k))
	}
	sort.Ints(pcrSet)
	pcrs := make([]pcr, len(pcrSet))
	for i, index := range pcrSet {
		pcrs[i].Digest = quotePcrs[uint32(index)]
		pcrs[i].Index = index
	}

	attInfo := attestationInfo{
		AttestationProtocolVersion: "2.0",
		IsolationInfo: isolationInfo{
			Evidence: evidence{
				Proof: proof{
					SnpReport:     params.SNPReport,
					VcekCertChain: append(append([]byte{}, params.VcekCert...), params.VcekChain...),
				},
				RunTimeData: params.RuntimeData,
			},
			Type: "SevSnp",
		},
		OSBuild:  infoString(OSBuild),
		OSDistro: infoString(OSDistro),
		OSType:   infoString(OSType),
		TcgLogs:  eventLog,
		TpmInfo: tpmInfo{
			AikCert:                    params.Attestation.AkCert,
			AikPub:                     akPub,
			EncKeyCertifyInfo:          params.EncKeyCertInfo,
			EncKeyCertifyInfoSignature: params.EncKeyCertInfoSig,
			EncKeyPub:                  params.EncKey,
			PCRs:                       pcrs,
			PcrQuote:                   quote.Quote,
			PcrSet:                     pcrSet,
			PcrSignature:               pcrSig,
		},
	}

	return attInfo, nil
}

func (a attestationInfo) MarshalJSON() ([]byte, error) {
	type otherTypeToPreventRecursion attestationInfo
	marshaled, err := json.Marshal(otherTypeToPreventRecursion(a))
	if err != nil {
		return nil, err
	}
	return marshalURLEncoded(marshaled), nil
}

func (a *attestationInfo) UnmarshalJSON(data []byte) error {
	unmarshaled, err := unmarshalURLEncoded(data)
	if err != nil {
		return err
	}
	type otherTypeToPreventRecursion attestationInfo
	return json.Unmarshal(unmarshaled, (*otherTypeToPreventRecursion)(a))
}

type clientPayload struct {
	Nonce []byte `json:"nonce"`
}

type isolationInfo struct {
	Evidence evidence
	Type     string
}

type evidence struct {
	Proof       proof
	RunTimeData []byte
}

type proof struct {
	SnpReport     reportBytes
	VcekCertChain []byte
}

func (p proof) MarshalJSON() ([]byte, error) {
	type otherTypeToPreventRecursion proof
	marshaled, err := json.Marshal(otherTypeToPreventRecursion(p))
	if err != nil {
		return nil, err
	}
	return json.Marshal(marshaled)
}

func (p *proof) UnmarshalJSON(data []byte) error {
	var unmarshaled []byte
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		return err
	}
	type otherTypeToPreventRecursion proof
	return json.Unmarshal(unmarshaled, (*otherTypeToPreventRecursion)(p))
}

type tpmInfo struct {
	AikCert                    []byte
	AikPub                     []byte
	EncKeyCertifyInfo          []byte
	EncKeyCertifyInfoSignature []byte
	EncKeyPub                  []byte
	PCRs                       []pcr
	PcrQuote                   []byte
	PcrSet                     []int
	PcrSignature               []byte
}

type pcr struct {
	Digest []byte
	Index  int
}

// infoString is a string that holds information about the issuer's system. It's encoded as base64 when marshaled to JSON.
type infoString string

func (s infoString) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(s))
}

func (s *infoString) UnmarshalJSON(data []byte) error {
	var unmarshaled []byte
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		return err
	}
	*s = infoString(unmarshaled)
	return nil
}

// reportBytes is the type of the raw SNP report. It's encoded as raw base64url when marshaled to JSON.
type reportBytes []byte

func (r reportBytes) MarshalJSON() ([]byte, error) {
	return marshalURLEncoded(r), nil
}

func (r *reportBytes) UnmarshalJSON(data []byte) error {
	unmarshaled, err := unmarshalURLEncoded(data)
	if err != nil {
		return err
	}
	*r = reportBytes(unmarshaled)
	return nil
}
