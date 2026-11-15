package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var adminUIFiles embed.FS

func adminUIHandler() http.Handler {
	uiFS, err := fs.Sub(adminUIFiles, "web")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(uiFS))
}
