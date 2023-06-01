# Makefile to regenerate mock files.

all: db/db.go state/state.go requests/requests.go
.PHONY: all

db/db.go: ../db/client.go
	mockgen --destination $@ --package db sigsum.org/log-go/internal/db Client 

state/state.go: ../state/state_manager.go
	mockgen --destination $@ --package state sigsum.org/log-go/internal/state StateManager

requests/requests.go:
	mockgen --destination $@ --package token sigsum.org/log-go/internal/requests TokenVerifier
