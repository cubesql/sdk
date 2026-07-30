cmake_minimum_required(VERSION 3.20)
project(CubeSQLODBC VERSION 1.0.0 LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "The first CubeSQL ODBC release targets Windows only")
endif()

option(CUBESQL_ODBC_WITH_TLS "Link the SDK's static LibreSSL library" ON)
set(CSDK "${CMAKE_CURRENT_SOURCE_DIR}/../C_SDK")

set(DRIVER_SOURCES
    src/driver.c
    src/setup.c
    ${CSDK}/cubesql.c
    ${CSDK}/crypt/pseudorandom.c
    ${CSDK}/crypt/aescrypt.c
    ${CSDK}/crypt/aeskey.c
    ${CSDK}/crypt/aestab.c
    ${CSDK}/crypt/base64.c
    ${CSDK}/crypt/sha1.c
    ${CSDK}/zlib/zlib.c
)

add_library(cubesqlodbc SHARED ${DRIVER_SOURCES})
target_compile_features(cubesqlodbc PRIVATE c_std_99)
target_compile_definitions(cubesqlodbc PRIVATE WIN32 CUBESQL_STATIC)
target_include_directories(cubesqlodbc PRIVATE include ${CSDK} ${CSDK}/crypt ${CSDK}/zlib)
target_link_libraries(cubesqlodbc PRIVATE ws2_32 shlwapi odbccp32 user32 advapi32 crypt32 bcrypt)
set_target_properties(cubesqlodbc PROPERTIES PREFIX "" OUTPUT_NAME "cubesqlodbc")

if(CUBESQL_ODBC_WITH_TLS)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(TLS_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/../libs/win-64bit/tls.lib")
    else()
        set(TLS_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/../libs/win-32bit/tls.lib")
    endif()
    if(NOT EXISTS "${TLS_LIBRARY}")
        message(FATAL_ERROR "LibreSSL library not found: ${TLS_LIBRARY}")
    endif()
    target_link_libraries(cubesqlodbc PRIVATE "${TLS_LIBRARY}")
else()
    target_compile_definitions(cubesqlodbc PRIVATE CUBESQL_DISABLE_SSL_ENCRYPTION)
endif()

if(MSVC)
    set_property(TARGET cubesqlodbc PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(cubesqlodbc PRIVATE legacy_stdio_definitions)
    target_compile_options(cubesqlodbc PRIVATE /W4 /wd4005 /wd4068 /wd4244 /wd4267
        $<$<CONFIG:Release>:/Zi>)
    target_link_options(cubesqlodbc PRIVATE
        /DEF:${CMAKE_CURRENT_SOURCE_DIR}/windows/cubesqlodbc.def
        $<$<CONFIG:Release>:/DEBUG>)
else()
    target_compile_options(cubesqlodbc PRIVATE -Wall -Wextra -Wno-misleading-indentation
        -Wno-multichar -Wno-attributes -Wno-macro-redefined)
    target_sources(cubesqlodbc PRIVATE windows/cubesqlodbc.def)
    target_link_options(cubesqlodbc PRIVATE -Wl,--kill-at)
endif()

install(TARGETS cubesqlodbc RUNTIME DESTINATION bin)
install(FILES windows/install.ps1 windows/uninstall.ps1 README.md DESTINATION .)

include(CTest)
if(BUILD_TESTING)
    add_executable(cubesql_odbc_smoke tests/test_windows.c)
    target_compile_definitions(cubesql_odbc_smoke PRIVATE ODBCVER=0x0380)
    target_link_libraries(cubesql_odbc_smoke PRIVATE odbc32 dbghelp)
    if(MSVC)
        target_compile_options(cubesql_odbc_smoke PRIVATE $<$<CONFIG:Release>:/Zi>)
        target_link_options(cubesql_odbc_smoke PRIVATE $<$<CONFIG:Release>:/DEBUG>)
    endif()
    add_test(NAME cubesql_odbc_smoke COMMAND cubesql_odbc_smoke)
endif()
