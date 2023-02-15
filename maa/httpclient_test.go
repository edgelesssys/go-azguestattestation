package maa

import (
	"io"
	"net/http"
	"strings"
)

type stubHttpClient struct {
	requests   []*http.Request
	respStatus int
	respBody   string
}

func (h *stubHttpClient) Do(req *http.Request) (*http.Response, error) {
	h.requests = append(h.requests, req)
	return &http.Response{StatusCode: h.respStatus, Body: io.NopCloser(strings.NewReader(h.respBody))}, nil
}
