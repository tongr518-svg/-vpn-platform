package main

import "testing"

func TestNewRouterRegistersRoutes(t *testing.T) {
	if handler := newRouter(&API{}); handler == nil {
		t.Fatal("newRouter returned a nil handler")
	}
}
