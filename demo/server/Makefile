.PHONY: all windows clean

# Default target: build for Linux
all: run

run:
	go build -o demo-srv ./demo-server.go
	mv demo-srv* ../bin/
# Build for Windows
windows:
	GOOS=windows GOARCH=amd64 go build -o demo-srv.exe ./demo-server.go
	mv demo-srv* ../bin/

clean:
	rm -f demo-srv demo-srv.exe
