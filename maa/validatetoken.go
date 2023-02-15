package maa

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// ValidateToken validates an MAA token and returns the claims.
func ValidateToken(token string, keySet []byte) (map[string]interface{}, error) {
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	parsedKeySet, err := parseKeySet(keySet)
	if err != nil {
		return nil, fmt.Errorf("parsing key set: %w", err)
	}

	var publicClaims jwt.Claims
	var privateClaims map[string]interface{}
	if err := parsedToken.Claims(&parsedKeySet, &publicClaims, &privateClaims); err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}
	if err := publicClaims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("validating claims: %w", err)
	}

	return privateClaims, nil
}

// GetKeySet gets the key set required to validate an MAA token.
func GetKeySet(ctx context.Context, maaURL string, httpClient HttpClient) ([]byte, error) {
	if maaURL == "" {
		return nil, errors.New("maaURL is empty")
	}
	maaURL, err := url.JoinPath(maaURL, "certs")
	if err != nil {
		return nil, fmt.Errorf("parsing maaURL: %w", err)
	}
	keySet, err := httpGet(ctx, maaURL, httpClient)
	if err != nil {
		return nil, err
	}
	if len(keySet) == 0 {
		return nil, errors.New("received empty response from MAA")
	}
	return keySet, nil
}

func parseKeySet(keySetBytes []byte) (jose.JSONWebKeySet, error) {
	var rawKeySet rawKeySet
	if err := json.Unmarshal(keySetBytes, &rawKeySet); err != nil {
		return jose.JSONWebKeySet{}, err
	}

	var keySet jose.JSONWebKeySet
	for _, key := range rawKeySet.Keys {
		if len(key.X5c) < 1 {
			continue
		}
		cert, err := x509.ParseCertificate(key.X5c[0])
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		keySet.Keys = append(keySet.Keys, jose.JSONWebKey{KeyID: key.Kid, Key: cert.PublicKey})
	}

	return keySet, nil
}

func httpGet(ctx context.Context, url string, httpClient HttpClient) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

type rawKeySet struct {
	Keys []rawKey
}

type rawKey struct {
	X5c [][]byte
	Kid string
}
