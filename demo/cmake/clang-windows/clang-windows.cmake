# Cross toolchain configuration for using clang-cl.
function(generate_vfs_overlay)
	unset(include_dirs)
	file(GLOB_RECURSE entries LIST_DIRECTORIES true "${WINSDK_INCLUDE}/*")
	foreach(entry ${entries})
		if(IS_DIRECTORY "${entry}")
			list(APPEND include_dirs "${entry}")
		endif()
	endforeach()

	file(WRITE "${CMAKE_BINARY_DIR}/winsdk_vfs_overlay.yaml" "version: 0\ncase-sensitive: false\nroots:\n")
	if(NOT include_dirs)
	  # If no include dirs found (e.g. WDK not installed), write an empty array to prevent YAML parse errors
	  file(APPEND "${CMAKE_BINARY_DIR}/winsdk_vfs_overlay.yaml" "  []\n")
	  return()
	endif()
	foreach(dir ${include_dirs})
		file(GLOB headers RELATIVE "${dir}" "${dir}/*.h")
		if(NOT headers)
			continue()
		endif()

		file(APPEND "${CMAKE_BINARY_DIR}/winsdk_vfs_overlay.yaml" "  - name: \"${dir}\"\n    type: directory\n    contents:\n")
		foreach(header ${headers})
			file(APPEND "${CMAKE_BINARY_DIR}/winsdk_vfs_overlay.yaml" "      - name: \"${header}\"\n        type: file\n        external-contents: \"${dir}/${header}\"\n")
		endforeach()
	endforeach()
endfunction()

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 6.1.7601) # Windows 7 SP1

set(CMAKE_C_COMPILER_TARGET ${_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${_TRIPLE})

if(NOT DEFINED $ENV{CLANG_BIN_DIR})
	set(CLANG_BIN_DIR "/usr/bin")
else()
	set(CLANG_BIN_DIR $ENV{CLANG_BIN_DIR})
endif()

set(CMAKE_C_COMPILER "${CLANG_BIN_DIR}/clang-cl-20")
set(CMAKE_CXX_COMPILER "${CLANG_BIN_DIR}/clang-cl-20")
set(CMAKE_RC_COMPILER "${CLANG_BIN_DIR}/llvm-rc-20")
set(CMAKE_LINKER "${CLANG_BIN_DIR}/lld-link-20")
set(CMAKE_AR "${CLANG_BIN_DIR}/llvm-lib-20")

include(${CMAKE_CURRENT_LIST_DIR}/config.cmake)

set(MSVC_INCLUDE "${MSVC_BASE}/include")
set(MSVC_LIB "${MSVC_BASE}/lib")

set(WINSDK_INCLUDE "${WINSDK_BASE}/Include/${WINSDK_VER}")
set(WINSDK_LIB "${WINSDK_BASE}/Lib/${WINSDK_VER}")

generate_vfs_overlay()
set(CMAKE_CLANG_VFS_OVERLAY "${CMAKE_BINARY_DIR}/winsdk_vfs_overlay.yaml")

set(COMPILE_FLAGS
	-imsvc "'${MSVC_INCLUDE}'"
	-imsvc "'${WINSDK_INCLUDE}/ucrt'"
	-imsvc "'${WINSDK_INCLUDE}/shared'"
	-imsvc "'${WINSDK_INCLUDE}/um'"
	-imsvc "'${WINSDK_INCLUDE}/winrt'"
	/EHa
)

set(CMAKE_RC_FLAGS_INIT "\
    /I '${MSVC_INCLUDE}' \
	/I '${WINSDK_INCLUDE}/ucrt' \
	/I '${WINSDK_INCLUDE}/shared' \
	/I '${WINSDK_INCLUDE}/um' \
	/I '${WINSDK_INCLUDE}/winrt' \
")

string(REPLACE ";" " " COMPILE_FLAGS "${COMPILE_FLAGS}")

set(CMAKE_C_FLAGS_INIT "${COMPILE_FLAGS}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_INIT "${COMPILE_FLAGS}" CACHE STRING "" FORCE)

set(LINK_FLAGS
    /manifest:no
	-libpath:"${MSVC_LIB}/${_ARCH}"
	-libpath:"${WINSDK_LIB}/ucrt/${_ARCH}"
	-libpath:"${WINSDK_LIB}/um/${_ARCH}"
)

string(REPLACE ";" " " LINK_FLAGS "${LINK_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS_INIT "${LINK_FLAGS}" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${LINK_FLAGS}" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${LINK_FLAGS}" CACHE STRING "" FORCE)

set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> ${LINK_FLAGS} <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> ${LINK_FLAGS} <TARGET> <LINK_FLAGS> <OBJECTS>")

set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_NO_WARNINGS ON)
