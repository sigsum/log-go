# Makefile to regenerate mock files.

db/db.go: ../db/client.go
	mockgen --destination $@ --package db sigsum.org/log-go/internal/db Client 
