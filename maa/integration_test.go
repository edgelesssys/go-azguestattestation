//go:build integration

package maa

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttestAndValidate(t *testing.T) {
	const maaURL = "https://sharedeus.eus.attest.azure.net"
	require := require.New(t)
	ctx := context.Background()
	nonce := []byte{2, 3}

	token, err := Attest(ctx, nonce, maaURL, http.DefaultClient)
	require.NoError(err)
	keySet, err := GetKeySet(ctx, maaURL, http.DefaultClient)
	require.NoError(err)
	claims, err := ValidateToken(token, keySet)
	require.NoError(err)
	require.Equal(base64.StdEncoding.EncodeToString(nonce), claims["x-ms-runtime"].(map[string]interface{})["client-payload"].(map[string]interface{})["nonce"])
}
