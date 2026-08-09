cmake_minimum_required(VERSION 3.20)
# Keep in step with include/cubesql_odbc_version.h, which the driver and the
# Windows resource script both read.
project(CubeSQLODBC VERSION 1.2.2 LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "The first CubeSQL ODBC release targets Windows only")
endif()

option(CUBESQL_ODBC_WITH_TLS "Link the SDK's static LibreSSL library" ON)
set(CSDK "${CMAKE_CURRENT_SOURCE_DIR}/../C_SDK")

enable_language(RC)

set(DRIVER_SOURCES
    src/driver.c
    src/setup.c
    windows/cubesqlodbc.rc
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

# The resource compiler does not define _WIN64, so the architecture shown in the
# version resource has to be passed in explicitly. target_compile_definitions
# reaches both the C compiler and the resource compiler.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(cubesqlodbc PRIVATE CSODBC_ARCH_64=1)
else()
    target_compile_definitions(cubesqlodbc PRIVATE CSODBC_ARCH_64=0)
endif()
target_include_directories(cubesqlodbc PRIVATE include ${CSDK} ${CSDK}/crypt ${CSDK}/zlib)
set_source_files_properties(windows/cubesqlodbc.rc PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(cubesqlodbc PRIVATE ws2_32 shlwapi odbccp32 comctl32 user32 advapi32 crypt32 bcrypt)
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
    # ------------------------------------------------------------------
    # Coordinate del server usato dai test. Vivono qui e non nella shell di
    # chi lancia, cosi' "ctest" funziona da solo e resta configurabile.
    # ------------------------------------------------------------------
    set(CUBESQL_TEST_HOST "127.0.0.1" CACHE STRING "Host del server CubeSQL per i test")
    set(CUBESQL_TEST_PORT "4430"      CACHE STRING "Porta del server CubeSQL per i test")
    set(CUBESQL_TEST_USER "admin"     CACHE STRING "Utente per i test")
    set(CUBESQL_TEST_PASSWORD "admin" CACHE STRING "Password per i test")

    set(CS_TEST_ENV
        "CUBESQL_ODBC_HOST=${CUBESQL_TEST_HOST}"
        "CUBESQL_ODBC_PORT=${CUBESQL_TEST_PORT}"
        "CUBESQL_ODBC_USER=${CUBESQL_TEST_USER}"
        "CUBESQL_ODBC_PASSWORD=${CUBESQL_TEST_PASSWORD}")

    # I punti e virgola vanno protetti: per CMake separano gli elementi di lista.
    set(CS_SMOKE_CONN
        "DRIVER={CubeSQL ODBC Driver}\;SERVER=${CUBESQL_TEST_HOST}\;PORT=${CUBESQL_TEST_PORT}\;UID=${CUBESQL_TEST_USER}\;PWD=${CUBESQL_TEST_PASSWORD}\;ENCRYPTION=NONE\;TIMEOUT=12\;")
    # ------------------------------------------------------------------
    # Test che passano dal Driver Manager vero (serve il driver registrato).
    # ------------------------------------------------------------------
    add_executable(cubesql_odbc_smoke tests/test_windows.c)
    target_compile_definitions(cubesql_odbc_smoke PRIVATE ODBCVER=0x0380)
    target_link_libraries(cubesql_odbc_smoke PRIVATE odbc32)
    if(MSVC)
        target_compile_options(cubesql_odbc_smoke PRIVATE $<$<CONFIG:Release>:/Zi>)
        target_link_options(cubesql_odbc_smoke PRIVATE $<$<CONFIG:Release>:/DEBUG>)
    endif()
    add_test(NAME cubesql_odbc_smoke COMMAND cubesql_odbc_smoke)
    set_tests_properties(cubesql_odbc_smoke PROPERTIES ENVIRONMENT
        "CUBESQL_ODBC_CONNECTION_STRING=${CS_SMOKE_CONN}")

    # ------------------------------------------------------------------
    # Test che compilano il driver dentro l'eseguibile e lo chiamano
    # direttamente, senza Driver Manager: non serve registrare nulla.
    #
    # Erano raggiungibili solo dal Makefile POSIX, quindi su Windows non
    # venivano mai compilati ne' eseguiti: 800 righe di copertura ferme, e
    # con esse l'unico test di concorrenza, proprio mentre il locking da
    # verificare (CRITICAL_SECTION) esiste solo qui.
    # ------------------------------------------------------------------
    set(CS_TEST_DRIVER_SOURCES
        src/driver.c
        src/setup.c
        ${CSDK}/cubesql.c
        ${CSDK}/crypt/pseudorandom.c
        ${CSDK}/crypt/aescrypt.c
        ${CSDK}/crypt/aeskey.c
        ${CSDK}/crypt/aestab.c
        ${CSDK}/crypt/base64.c
        ${CSDK}/crypt/sha1.c
        ${CSDK}/zlib/zlib.c)

    # core e types non hanno bisogno di un server; gli altri si'.
    set(CS_DIRECT_TESTS core conformance integration types unicode diagnostics setup aliases)

    foreach(cs_t IN LISTS CS_DIRECT_TESTS)
        set(cs_target cubesql_odbc_${cs_t})
        add_executable(${cs_target} tests/test_${cs_t}.c ${CS_TEST_DRIVER_SOURCES})
        target_compile_features(${cs_target} PRIVATE c_std_99)
        target_compile_definitions(${cs_target} PRIVATE WIN32 CUBESQL_STATIC)
        target_include_directories(${cs_target} PRIVATE include ${CSDK} ${CSDK}/crypt ${CSDK}/zlib)
        target_link_libraries(${cs_target} PRIVATE ws2_32 shlwapi odbccp32 comctl32 user32 advapi32 crypt32 bcrypt)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_compile_definitions(${cs_target} PRIVATE CSODBC_ARCH_64=1)
        else()
            target_compile_definitions(${cs_target} PRIVATE CSODBC_ARCH_64=0)
        endif()
        if(CUBESQL_ODBC_WITH_TLS)
            target_link_libraries(${cs_target} PRIVATE "${TLS_LIBRARY}")
        else()
            target_compile_definitions(${cs_target} PRIVATE CUBESQL_DISABLE_SSL_ENCRYPTION)
        endif()
        if(MSVC)
            set_property(TARGET ${cs_target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
            target_link_libraries(${cs_target} PRIVATE legacy_stdio_definitions)
            target_compile_options(${cs_target} PRIVATE /W4 /wd4005 /wd4068 /wd4244 /wd4267
                $<$<CONFIG:Release>:/Zi>)
            target_link_options(${cs_target} PRIVATE $<$<CONFIG:Release>:/DEBUG>)
        endif()
        add_test(NAME ${cs_target} COMMAND ${cs_target})
        set_tests_properties(${cs_target} PROPERTIES ENVIRONMENT "${CS_TEST_ENV}")
    endforeach()

    # ------------------------------------------------------------------
    # Gli script di registrazione, che nessun test eseguiva: due difetti
    # bloccanti stavano li'. Scrivono in HKLM, quindi senza privilegi
    # elevati il test si dichiara saltato invece di fallire.
    # ------------------------------------------------------------------
    find_program(CS_POWERSHELL NAMES powershell.exe pwsh.exe)
    if(CS_POWERSHELL)
        # il DLL costruito qui e' di questa architettura: va passato nel
        # parametro giusto, altrimenti il test verificherebbe il ramo sbagliato
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(CS_DRIVER_ARG -Driver64)
        else()
            set(CS_DRIVER_ARG -Driver32)
        endif()
        add_test(NAME cubesql_odbc_install_scripts
            COMMAND "${CS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_install_scripts.ps1"
                ${CS_DRIVER_ARG} "$<TARGET_FILE:cubesqlodbc>"
                -ScriptDir "${CMAKE_CURRENT_SOURCE_DIR}/windows")
        set_tests_properties(cubesql_odbc_install_scripts PROPERTIES SKIP_RETURN_CODE 77)
    endif()
endif()
