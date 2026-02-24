# Run with: $ docker build -o . .
# Should output a tarball to the directory.
FROM ubuntu:24.04 AS builder

WORKDIR /build

RUN apt update && \
    apt install -y --no-install-recommends build-essential wget curl git apt-transport-https lsb-release software-properties-common gnupg \
    gcc-mingw-w64-i686

RUN wget https://gist.githubusercontent.com/Danukeru/ddad77d1c16ef894f0a2684c3fb1100f/raw/335d4d935db51f47a9086fd8d005342bf76de3aa/go-updater.sh && \
    chmod +x go-updater.sh && ./go-updater.sh

ENV PATH=/usr/local/go/bin:$PATH

RUN git clone https://github.com/Danukeru/KLINIKAL klinikal && \
    cd klinikal && \
    make

RUN tar zcvf klinikal.tar.gz klinikal

FROM scratch
COPY --from=builder /build/klinikal.tar.gz /
