# Building the Windows demo

The supported reproducible build is a Linux Docker cross-build for Windows
x86 with LLVM/Clang 22:

```sh
docker build -f demo/Dockerfile --target artifact -o type=local,dest=demo/out .
```

The resulting executable is `demo/out/demo.exe`. The build downloads MSVC
17.14 and Windows SDK 10.0.26100 through the repository-pinned
[`vsdownload.py`](https://gist.githubusercontent.com/Danukeru/e5e7cf6050519551844a3134cfa9a23c/raw/fa06e2104d82ee14eef3799a3a8e784bce9460a2/vsdownload.py)
revision, cross-compiles with `clang-cl-22`, and verifies the output is an x86
COFF executable.

The host filesystem and KLINIKAL source paths remain case-sensitive. Microsoft
headers and import libraries have mixed filename casing even when their own
callers use another spelling. The Docker build creates hard-link aliases only
inside `/opt/wdk`; it does not use casefold ext4 or alter project paths.

`build.sh` is a wrapper for the same Docker command when run from `demo/`.
The legacy Clang 20/i686 toolchain has been removed; the Docker build uses
only `cmake/clang22-windows-x86.cmake`.
