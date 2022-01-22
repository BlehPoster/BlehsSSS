cmake_minimum_required(VERSION 3.10)
project(blehsss)

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
)

add_executable(test
    testing/main.cpp
)

include_directories(.)
include_directories(src)

target_compile_features(c25519 PRIVATE cxx_std_17)
target_compile_features(blehsss PRIVATE cxx_std_17)
target_compile_features(test PRIVATE cxx_std_17)

target_link_libraries(test PRIVATE blehsss c25519)