package maa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const (
	lenHclHeader                   = 0x20
	lenSnpReport                   = 0x4a0
	lenSnpReportRuntimeDataPadding = 0x14
	thimURL                        = "http://169.254.169.254/metadata/THIM/amd/certification"
)

type Parameters struct {
	SNPReport         []byte
	RuntimeData       []byte
	VcekCert          []byte
	VcekChain         []byte
	Attestation       *Attestation
	EncKey            []byte
	EncKeyCertInfo    []byte
	EncKeyCertInfoSig []byte
}

// NewParameters collects all data that the MAA requires from the issuer's system.
func NewParameters(ctx context.Context, nonce []byte, httpClient HttpClient) (Parameters, error) {
	tpm, err := newTPM()
	if err != nil {
		return Parameters{}, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()
	return newParameters(ctx, nonce, httpClient, tpm)
}

func newParameters(ctx context.Context, nonce []byte, httpClient HttpClient, tpm *tpm) (Parameters, error) {
	vcekCert, vcekChain, err := getVCEK(ctx, httpClient)
	if err != nil {
		return Parameters{}, fmt.Errorf("getting VCEK: %w", err)
	}

	attestation, err := tpm.attest(nonce)
	if err != nil {
		return Parameters{}, fmt.Errorf("creating attestation: %w", err)
	}

	hclReport, err := tpm.getHCLReport()
	if err != nil {
		return Parameters{}, fmt.Errorf("getting HCL report: %w", err)
	}
	if len(hclReport) <= lenHclHeader+lenSnpReport+lenSnpReportRuntimeDataPadding {
		return Parameters{}, errors.New("report read from TPM is shorter than expected")
	}
	hclReport = hclReport[lenHclHeader:]

	encKey, encKeyCertInfo, encKeyCertInfoSig, err := tpm.getEncryptionKey(attestation.Quotes)
	if err != nil {
		return Parameters{}, fmt.Errorf("getting encryption key: %w", err)
	}

	runtimeData, _, _ := bytes.Cut(hclReport[lenSnpReport+lenSnpReportRuntimeDataPadding:], []byte{0})

	return Parameters{
		SNPReport:         hclReport[:lenSnpReport],
		RuntimeData:       runtimeData,
		VcekCert:          []byte(vcekCert),
		VcekChain:         []byte(vcekChain),
		Attestation:       attestation,
		EncKey:            encKey,
		EncKeyCertInfo:    encKeyCertInfo,
		EncKeyCertInfoSig: encKeyCertInfoSig,
	}, nil
}

func getVCEK(ctx context.Context, httpClient HttpClient) (cert, chain string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, thimURL, http.NoBody)
	if err != nil {
		return "", "", err
	}
	req.Header.Add("Metadata", "True")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", errors.New(resp.Status)
	}
	var vcekResp struct {
		VcekCert         string
		CertificateChain string
	}
	if err := json.NewDecoder(resp.Body).Decode(&vcekResp); err != nil {
		return "", "", err
	}
	if vcekResp.VcekCert == "" || vcekResp.CertificateChain == "" {
		return "", "", errors.New("missing data in response")
	}
	return vcekResp.VcekCert, vcekResp.CertificateChain, nil
}
