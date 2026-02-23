#!/usr/bin/env bash

# build.sh - Build demo.exe using CMake and clang-windows-cmake on clang-20
# Create a build directory
mkdir -p build
cd build

echo "Configuring CMake with clang-windows-cmake toolchain..."

# Configure CMake using the toolchain file
#ARCH=x86_64
ARCH=i686
cmake .. \
      -DCMAKE_TOOLCHAIN_FILE=../cmake/clang-windows/clang-windows-$ARCH.cmake \
      -DCMAKE_CXX_COMPILER_WORKS=1 \
      -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo "CMake configuration failed."
    exit 1
fi

echo "Building demo.exe..."

# Build the project
cmake --build .

if [ $? -eq 0 ]; then
    echo "Build successful: build/demo.exe"
    # Copy out to demo directory
    cp demo.exe ../bin/
else
    echo "Build failed."
    exit 1
fi
