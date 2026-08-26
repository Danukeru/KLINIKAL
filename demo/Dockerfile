# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04 AS clang22-base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl wget lsb-release gnupg software-properties-common \
       cmake ninja-build python3 msitools \
    && wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh \
    && chmod +x /tmp/llvm.sh \
    && /tmp/llvm.sh 22 all \
    && rm -f /tmp/llvm.sh \
    && rm -rf /var/lib/apt/lists/*

FROM clang22-base AS windows-toolchain
COPY demo/tools/prepare_windows_sdk_aliases.py /usr/local/bin/prepare_windows_sdk_aliases.py
# The source tree and Linux filesystem remain case-sensitive.  Aliases exist
# only within the downloaded Microsoft SDK/MSVC tree, whose own headers and
# import libraries use mixed filename casing.
ARG VSDOWNLOAD_URL=https://gist.githubusercontent.com/Danukeru/e5e7cf6050519551844a3134cfa9a23c/raw/fa06e2104d82ee14eef3799a3a8e784bce9460a2/vsdownload.py
RUN --mount=type=cache,target=/var/cache/vsdownload \
    curl -fsSL "$VSDOWNLOAD_URL" -o /tmp/vsdownload.py \
    && python3 /tmp/vsdownload.py --accept-license \
         --dest /opt/wdk --cache /var/cache/vsdownload \
         --msvc-version 17.14 --sdk-version 10.0.26100 --skip-recommended \
         --architecture x64 --host-arch x64 \
    && ln -sfn "/opt/wdk/Windows Kits" /opt/wdk/WindowsKits \
    && python3 /usr/local/bin/prepare_windows_sdk_aliases.py \
         /opt/wdk/VC/Tools/MSVC/*/include \
         /opt/wdk/WindowsKits/10/Include/*/ucrt \
         /opt/wdk/WindowsKits/10/Include/*/shared \
         /opt/wdk/WindowsKits/10/Include/*/um \
         /opt/wdk/WindowsKits/10/Include/*/winrt

FROM windows-toolchain AS windows-cross
WORKDIR /src/KLINIKAL
COPY . /src/KLINIKAL
RUN python3 demo/tools/prepare_windows_sdk_aliases.py \
         /opt/wdk/VC/Tools/MSVC/*/include \
         /opt/wdk/WindowsKits/10/Include/*/ucrt \
         /opt/wdk/WindowsKits/10/Include/*/shared \
         /opt/wdk/WindowsKits/10/Include/*/um \
         /opt/wdk/WindowsKits/10/Include/*/winrt \
    && python3 demo/tools/prepare_windows_sdk_aliases.py --aliases-only \
         /opt/wdk/VC/Tools/MSVC/*/lib \
         /opt/wdk/WindowsKits/10/Lib/*/ucrt \
         /opt/wdk/WindowsKits/10/Lib/*/um \
    && python3 demo/tools/audit_case_sensitivity.py /src/KLINIKAL/demo \
    && cmake -G Ninja -S demo -B build-windows-clang22 \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_TOOLCHAIN_FILE=/src/KLINIKAL/demo/cmake/clang22-windows-x64.cmake \
    && cmake --build build-windows-clang22 --parallel \
    && cmake --build build-windows-clang22 --target case-audit \
    && test -f build-windows-clang22/demo.exe \
    && llvm-readobj-22 --file-headers build-windows-clang22/demo.exe \
       | grep -q 'COFF-x86-64'

FROM scratch AS artifact
COPY --from=windows-cross /src/KLINIKAL/build-windows-clang22/demo.exe /demo.exe
