package main

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed "atproto-wallet-login.html"
var tmplAtProtoWalletLoginText string
var tmplAtProtoWalletLogin = template.Must(template.Must(template.New("atproto-wallet-login.html").Parse(tmplBaseText)).Parse(tmplAtProtoWalletLoginText))

func (s *Server) AtprotoWalletLogin(w http.ResponseWriter, r *http.Request) {
	tmplAtProtoWalletLogin.Execute(w, nil)
}
