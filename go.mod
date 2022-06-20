module git.sigsum.org/log-go

go 1.15

replace git.sigsum.org/sigsum-go => /home/rgdd/src/git.sigsum.org/sigsum-go

require (
	git.sigsum.org/sigsum-go v0.0.7
	github.com/golang/mock v1.4.4
	github.com/google/certificate-transparency-go v1.1.1 // indirect
	github.com/google/trillian v1.3.13
	github.com/prometheus/client_golang v1.9.0
	google.golang.org/grpc v1.36.0
)
