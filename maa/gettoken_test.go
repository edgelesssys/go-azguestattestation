package maa

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	ptpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEncryptedToken(t *testing.T) {
	nonce := []byte{2}

	params := Parameters{
		SNPReport:   []byte("aa>a"), // some value that is different for Base64 Std and URL encoding
		RuntimeData: []byte("runtimedata"),
		VcekCert:    []byte("vcekcert"),
		VcekChain:   []byte("vcekchain"),
		Attestation: &Attestation{
			AkPub: []byte("akpub"),
			Quotes: []*Quote{
				{
					Quote:  []byte("quote"),
					RawSig: []byte{0, 20, 0, 0, 0, 3, 1, 2, 3}, // TPMT_SIGNATURE with algo RSASSA
					Pcrs: &ptpm.PCRs{
						Hash: ptpm.HashAlgo_SHA256,
						Pcrs: map[uint32][]byte{3: {3, 3}, 1: {1, 1}},
					},
				},
			},
			EventLog: specIDEvent,
			AkCert:   []byte("akcert"),
		},
		EncKey:            []byte("enckey"),
		EncKeyCertInfo:    []byte("enckeycertinfo"),
		EncKeyCertInfoSig: []byte("enckeycertinfosig"),
	}

	wantAttestationInfo := attestationInfo{
		AttestationProtocolVersion: "2.0",
		ClientPayload:              clientPayload{nonce},
		IsolationInfo: isolationInfo{
			Evidence: evidence{
				Proof: proof{
					SnpReport:     []byte("aa>a"),
					VcekCertChain: []byte("vcekcertvcekchain"),
				},
				RunTimeData: []byte("runtimedata"),
			},
			Type: "SevSnp",
		},
		OSBuild:  "Edgeless",
		OSDistro: "Edgeless",
		OSType:   "Edgeless",
		TcgLogs:  specIDEvent,
		TpmInfo: tpmInfo{
			AikCert:                    []byte("akcert"),
			AikPub:                     append([]byte{0, 5}, []byte("akpub")...),
			EncKeyCertifyInfo:          []byte("enckeycertinfo"),
			EncKeyCertifyInfoSignature: []byte("enckeycertinfosig"),
			EncKeyPub:                  []byte("enckey"),
			PCRs:                       []pcr{{Digest: []byte{1, 1}, Index: 1}, {Digest: []byte{3, 3}, Index: 3}},
			PcrQuote:                   []byte("quote"),
			PcrSet:                     []int{1, 3},
			PcrSignature:               []byte{1, 2, 3},
		},
	}

	testCases := map[string]struct {
		params              Parameters
		url                 string
		httpClient          stubHttpClient
		wantToken           string
		wantAttestationInfo attestationInfo
		wantErr             bool
	}{
		"basic": {
			params:              params,
			url:                 "https://test",
			httpClient:          stubHttpClient{respStatus: http.StatusOK, respBody: `{"Token":"foo"}`},
			wantToken:           "foo",
			wantAttestationInfo: wantAttestationInfo,
		},
		"empty url": {
			params:     params,
			url:        "",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"Token":"foo"}`},
			wantErr:    true,
		},
		"invalid url": {
			params:     params,
			url:        "%",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"Token":"foo"}`},
			wantErr:    true,
		},
		"maa returns error": {
			params:     params,
			url:        "https://test",
			httpClient: stubHttpClient{respStatus: http.StatusNotFound},
			wantErr:    true,
		},
		"maa returns invalid response": {
			params:     params,
			url:        "https://test",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `foo`},
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			token, err := GetEncryptedToken(context.Background(), tc.params, nonce, tc.url, &tc.httpClient)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantToken, token)

			require.Len(tc.httpClient.requests, 1)
			req := tc.httpClient.requests[0]
			assert.Equal(tc.url+"/attest/AzureGuest?api-version=2020-10-01", req.URL.String())
			var attReq attestRequest
			require.NoError(json.NewDecoder(req.Body).Decode(&attReq))
			assert.Equal(tc.wantAttestationInfo, attReq.AttestationInfo)
		})
	}
}
