package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsTrailingData(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	tests := []struct {
		name string
		body string
	}{
		{
			name: "second JSON value",
			body: `{"name":"first"} {"name":"second"}`,
		},
		{
			name: "trailing text",
			body: `{"name":"first"} trailing`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/test",
				strings.NewReader(test.body),
			)
			recorder := httptest.NewRecorder()

			var decoded payload
			if decodeJSON(recorder, req, &decoded) {
				t.Fatal("应拒绝带有尾随内容的 JSON")
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("期望状态码 400，得到 %d", recorder.Code)
			}
		})
	}
}

func TestDecodeJSONAcceptsSingleObject(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/test",
		strings.NewReader(`{"name":"valid"}`),
	)
	recorder := httptest.NewRecorder()

	var decoded payload
	if !decodeJSON(recorder, req, &decoded) {
		t.Fatalf("有效 JSON 被拒绝：%s", recorder.Body.String())
	}
	if decoded.Name != "valid" {
		t.Fatalf("解码结果不正确：%q", decoded.Name)
	}
}
