# syntax=docker/dockerfile:1.7
# Builds the KLINIKAL runtime components. The 32-bit demo is built separately by
# demo/Dockerfile because it uses the pinned LLVM 22 MSVC-compatible toolchain.
FROM golang:1.25.5-bookworm AS dll-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# The historical demo is 32-bit, so its manually mapped Winsock replacement
# must be i686 too. The historical release name is retained for its loader.
RUN GOOS=windows GOARCH=386 CGO_ENABLED=1 \
      CC=i686-w64-mingw32-gcc \
      CGO_CFLAGS=-static \
    go build -buildmode=c-shared \
      -ldflags='-s -w -extldflags=-Wl,/src/ws2_32.def' \
      -o /out/wsx_32.dll

FROM golang:1.25.5-bookworm AS demo-server-builder

WORKDIR /src/demo/server
COPY demo/server/demo-server.go ./
RUN GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' \
      -o /out/demo-srv ./demo-server.go \
    && GOOS=windows GOARCH=386 go build -trimpath -ldflags='-s -w' \
      -o /out/demo-srv.exe ./demo-server.go

# This stage deliberately does not include demo.exe. The release workflow
# combines this directory with the output of demo/Dockerfile, then creates ZIP.
FROM scratch AS artifact
COPY --from=dll-builder /out/wsx_32.dll /klinikal/wsx_32.dll
COPY --from=demo-server-builder /out/demo-srv /klinikal/demo-srv
COPY --from=demo-server-builder /out/demo-srv.exe /klinikal/demo-srv.exe
COPY demo/howto.txt /klinikal/howto.txt
COPY wg.conf /klinikal/wg.conf
