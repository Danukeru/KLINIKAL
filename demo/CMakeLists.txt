cmake_minimum_required(VERSION 3.15)
project(KLINIKALDemo C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the executable
add_executable(demo main.cpp)
		    
target_include_directories(demo PRIVATE winpe/)

# Link against the WinSock2 library
target_link_libraries(demo ws2_32)

option(KLINIKAL_CASE_AUDIT "Add the case-sensitive project-path audit target" ON)
if(KLINIKAL_CASE_AUDIT)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_custom_target(case-audit
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/audit_case_sensitivity.py"
                    "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMENT "Checking demo paths on a case-sensitive filesystem")
    endif()
endif()
