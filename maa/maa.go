package maa

import (
	"context"
	"fmt"
	"net/http"
)

// Attest requests a JWT token from MAA for the current machine.
//
// This function combines NewParameters, GetEncryptedToken, and DecryptToken.
func Attest(ctx context.Context, nonce []byte, maaURL string, httpClient HttpClient) (string, error) {
	tpm, err := newTPM()
	if err != nil {
		return "", fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()
	params, err := newParameters(ctx, nonce, httpClient, tpm)
	if err != nil {
		return "", fmt.Errorf("getting system parameters: %w", err)
	}
	encryptedToken, err := GetEncryptedToken(ctx, params, nonce, maaURL, httpClient)
	if err != nil {
		return "", fmt.Errorf("getting token: %w", err)
	}
	token, err := decryptToken(encryptedToken, tpm)
	if err != nil {
		return "", fmt.Errorf("decrypting token: %w", err)
	}
	return token, nil
}

type HttpClient interface {
	Do(*http.Request) (*http.Response, error)
}
