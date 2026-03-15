cmake_minimum_required(VERSION 3.10.2)
project(eCMP LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -Wextra -Werror -g")

option(USE_PKCS11_HELPER_LIBRARY "Build mbed TLS with the pkcs11-helper library." OFF)
option(ENABLE_ZLIB_SUPPORT "Build mbed TLS with zlib library." OFF)
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../embeddedCMP/external/mbedtls/mbedtls/include
)

add_definitions(-DMBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../embeddedCMP/external/mbedtls/mbedtls/include/mbedtls/mbedtls_config.h")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../embeddedCMP/external/mbedtls/mbedtls
                 ${CMAKE_CURRENT_BINARY_DIR}/mbedtls)

set(ECMP_SOURCES
    src/ecmp_client.c
    src/ecmp_cmp.c
    src/ecmp_crypto_mbedtls.c
    src/ecmp_transport_http.c
)

add_library(ecmp STATIC ${ECMP_SOURCES})
target_link_libraries(ecmp PUBLIC mbedtls mbedx509)

add_executable(ecmp_client program/main.c)
target_link_libraries(ecmp_client PRIVATE ecmp)
