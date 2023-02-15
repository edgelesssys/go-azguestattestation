package maa

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParameters(t *testing.T) {
	testCases := map[string]struct {
		nonce         []byte
		httpClient    stubHttpClient
		wantVcekCert  string
		wantVcekChain string
		wantErr       bool
	}{
		"basic": {
			nonce:         []byte{2},
			httpClient:    stubHttpClient{respStatus: http.StatusOK, respBody: `{"VcekCert":"vcekcert","CertificateChain":"vcekchain"}`},
			wantVcekCert:  "vcekcert",
			wantVcekChain: "vcekchain",
		},
		"nil nonce": {
			nonce:      nil,
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"VcekCert":"vcekcert","CertificateChain":"vcekchain"}`},
			wantErr:    true,
		},
		"empty nonce": {
			nonce:      []byte{},
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"VcekCert":"vcekcert","CertificateChain":"vcekchain"}`},
			wantErr:    true,
		},
		"THIM returns error": {
			nonce:      []byte{2},
			httpClient: stubHttpClient{respStatus: http.StatusNotFound},
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// prepare HCL report
			snpReport := make([]byte, lenSnpReport)
			snpReport[0] = 2
			snpReport[len(snpReport)-1] = 3
			hclReport := append(make([]byte, lenHclHeader), snpReport...)
			hclReport = append(hclReport, make([]byte, lenSnpReportRuntimeDataPadding)...)
			hclReport = append(hclReport, []byte("runtimedata")...)

			// prepare simulated TPM
			sim, err := newSimTPM()
			require.NoError(err)
			defer sim.Close()
			require.NoError(sim.nvWrite(indexAKCert, []byte("akcert")))
			require.NoError(sim.nvWrite(indexHCLReport, hclReport))
			key, err := client.NewCachedKey(sim, tpm2.HandleOwner, client.AKTemplateRSA(), indexAKPub)
			require.NoError(err)
			key.Close()

			params, err := newParameters(context.Background(), tc.nonce, &tc.httpClient, &tpm{sim})
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Len(tc.httpClient.requests, 1)
			assert.Equal(snpReport, params.SNPReport)
			assert.EqualValues("runtimedata", params.RuntimeData)
			assert.EqualValues(tc.wantVcekCert, params.VcekCert)
			assert.EqualValues(tc.wantVcekChain, params.VcekChain)
			assert.EqualValues("akcert", params.Attestation.AkCert)
			assert.NotEmpty(params.EncKey)
			assert.NotEmpty(params.EncKeyCertInfo)
			assert.NotEmpty(params.EncKeyCertInfoSig)

			// check that nonce has been used for attestation
			quotes := params.Attestation.Quotes
			quoteIdx, err := getSHA256QuoteIndex(quotes)
			require.NoError(err)
			attestationData, err := tpm2.DecodeAttestationData(quotes[quoteIdx].Quote)
			require.NoError(err)
			assert.EqualValues(tc.nonce, attestationData.ExtraData)
		})
	}
}

func TestGetVCEK(t *testing.T) {
	testCases := map[string]struct {
		httpClient stubHttpClient
		wantCert   string
		wantChain  string
		wantErr    bool
	}{
		"THIM returns cert and chain": {
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"VcekCert":"cert","CertificateChain":"chain"}`},
			wantCert:   "cert",
			wantChain:  "chain",
		},
		"THIM returns error": {
			httpClient: stubHttpClient{respStatus: http.StatusNotFound},
			wantErr:    true,
		},
		"missing chain": {
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"VcekCert":"cert"}`},
			wantErr:    true,
		},
		"missing cert": {
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `{"CertificateChain":"chain"}`},
			wantErr:    true,
		},
		"empty response": {
			httpClient: stubHttpClient{respStatus: http.StatusOK},
			wantErr:    true,
		},
		"invalid response": {
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `foo`},
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			cert, chain, err := getVCEK(context.Background(), &tc.httpClient)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantCert, cert)
			assert.Equal(tc.wantChain, chain)

			require.Len(tc.httpClient.requests, 1)
			req := tc.httpClient.requests[0]
			assert.Equal(thimURL, req.URL.String())
			assert.Equal("True", req.Header.Get("Metadata"))
		})
	}
}
