cmake_minimum_required(VERSION 3.15)
project(KLINIKALDemo C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the executable
add_executable(demo main.cpp)
		    
target_include_directories(demo PRIVATE winpe/)

# Link against the WinSock2 library
target_link_libraries(demo ws2_32)
