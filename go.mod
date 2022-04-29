module github.com/rendicott/uggly-server-login

replace github.com/rendicott/uggo => ../uggo

replace github.com/rendicott/uggly => ../uggly

go 1.18

require (
	github.com/rendicott/uggly v0.1.2
	github.com/rendicott/uggo v0.0.2
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	google.golang.org/grpc v1.46.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20210917161153-d61c044b1678 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220401170504-314d38edb7de // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)
