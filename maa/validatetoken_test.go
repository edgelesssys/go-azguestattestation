package maa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateToken(t *testing.T) {
	requir := require.New(t)

	const kid = "foo"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	requir.NoError(err)

	// create key set
	certTemplate := &x509.Certificate{SerialNumber: &big.Int{}}
	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	requir.NoError(err)
	keySet, err := json.Marshal(rawKeySet{
		[]rawKey{
			{X5c: [][]byte{cert}, Kid: kid},
		},
	})
	requir.NoError(err)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	requir.NoError(err)

	testCases := map[string]struct {
		key     *rsa.PrivateKey
		claims  map[string]interface{}
		wantErr bool
	}{
		"basic": {
			key:    key,
			claims: map[string]interface{}{"str": "abc", "bool": true},
		},
		"no claims is ok": {
			key:    key,
			claims: map[string]interface{}{},
		},
		"other key": {
			key:     otherKey,
			claims:  map[string]interface{}{"str": "abc", "bool": true},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// create signed token
			signerOpts := (&jose.SignerOptions{}).WithHeader("kid", kid)
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: tc.key}, signerOpts)
			require.NoError(err)
			token, err := jwt.Signed(signer).Claims(tc.claims).CompactSerialize()
			require.NoError(err)

			claims, err := ValidateToken(token, keySet)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.claims, claims)
		})
	}
}

func TestGetKeySet(t *testing.T) {
	testCases := map[string]struct {
		url        string
		httpClient stubHttpClient
		wantKeySet []byte
		wantErr    bool
	}{
		"basic": {
			url:        "https://test",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `keyset`},
			wantKeySet: []byte("keyset"),
		},
		"empty url": {
			url:        "",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `keyset`},
			wantErr:    true,
		},
		"invalid url": {
			url:        "%",
			httpClient: stubHttpClient{respStatus: http.StatusOK, respBody: `keyset`},
			wantErr:    true,
		},
		"maa returns error": {
			url:        "https://test",
			httpClient: stubHttpClient{respStatus: http.StatusNotFound},
			wantErr:    true,
		},
		"empty response": {
			url:        "https://test",
			httpClient: stubHttpClient{respStatus: http.StatusOK},
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			keySet, err := GetKeySet(context.Background(), tc.url, &tc.httpClient)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantKeySet, keySet)

			require.Len(tc.httpClient.requests, 1)
			assert.Equal(tc.url+"/certs", tc.httpClient.requests[0].URL.String())
		})
	}
}
