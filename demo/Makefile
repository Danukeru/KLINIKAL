.PHONY: all clean

# Default target: build for Linux
all: build

build:
	mkdir bin
	cd server && make && make windows
	bash build.sh
clean:
	rm -rf build bin demo.exe demo server/demo-srv server/demo-srv.exe
