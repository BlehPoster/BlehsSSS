cmake_minimum_required(VERSION 3.10)
project(blehsss)

add_library(base64 STATIC
    deps/base64/base64.h
    deps/base64/base64.cpp
)

add_library(c25519 STATIC
    deps/c25519/src/c25519.h
    deps/c25519/src/c25519.c
    deps/c25519/src/ed25519.h
    deps/c25519/src/ed25519.c
    deps/c25519/src/edsign.h
    deps/c25519/src/edsign.c
    deps/c25519/src/f25519.h
    deps/c25519/src/f25519.c
    deps/c25519/src/fprime.h
    deps/c25519/src/fprime.c
    deps/c25519/src/morph25519.h
    deps/c25519/src/morph25519.c
    deps/c25519/src/sha512.h
    deps/c25519/src/sha512.c
)

add_library(aes STATIC
    deps/aes/aes.hpp
    deps/aes/aes.h
    deps/aes/aes.c
)

add_library(blehsss STATIC
    src/common/random.hpp
    src/common/random.cpp
    src/common/types.h
    src/sss/sss.h
    src/sss/sss.cpp
    src/c25519/c25519.h
    src/c25519/c25519.cpp
    src/ed25519/ed25519.h
    src/ed25519/ed25519.cpp
    src/ecies/ecies.h
    src/ecies/ecies.cpp
    src/blehsss.h
    src/blehsss.cpp
)

add_executable(test
    testing/main.cpp
)

add_executable(cli
    src/cli/main.cpp
)

include_directories(.)
include_directories(src)
include_directories(deps/)

target_compile_features(base64 PRIVATE cxx_std_17)
target_compile_features(c25519 PRIVATE cxx_std_17)
target_compile_features(blehsss PRIVATE cxx_std_17)
target_compile_features(test PRIVATE cxx_std_17)
target_compile_features(cli PRIVATE cxx_std_17)

target_link_libraries(test PRIVATE blehsss base64 c25519 aes)
target_link_libraries(cli PRIVATE blehsss base64 c25519 aes)