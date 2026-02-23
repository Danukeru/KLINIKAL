.PHONY: build clean

build:
	GOOS=windows GOARCH=386 CGO_ENABLED=1 CC=i686-w64-mingw32-gcc-win32 \
	CGO_CFLAGS="-static" \
	go build -x -buildmode=c-shared \
	-ldflags="-v -s -w -extldflags=-Wl,$(CURDIR)/ws2_32.def" \
	-o ws2_32.dll

clean:
	rm -f ws2_32.dll ws2_32.h
