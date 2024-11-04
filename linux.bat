SET GOOS=linux
SET GOARCH=amd64
go build -ldflags "-s -w -X main.version=v2.3.3"