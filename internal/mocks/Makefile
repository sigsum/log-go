# Makefile to regenerate mock files.

all: db/db.go state/state.go trillian/trillian.go
.PHONY: all

db/db.go: ../db/client.go
	go run github.com/golang/mock/mockgen --destination $@ --package db sigsum.org/log-go/internal/db Client

state/state.go: ../state/state_manager.go
	go run github.com/golang/mock/mockgen --destination $@ --package state sigsum.org/log-go/internal/state StateManager

trillian/trillian.go: ../../go.mod
	go run github.com/golang/mock/mockgen --destination $@ --package trillian github.com/google/trillian TrillianLogClient
