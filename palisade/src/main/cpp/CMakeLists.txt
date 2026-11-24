cmake_minimum_required(VERSION 3.22.1)
project(palisade C)

add_library(palisade SHARED palisade.c)

target_compile_options(palisade PRIVATE
    -Wall -Wextra -Werror
    -fstack-protector-strong
    -fvisibility=hidden)

# 16 KB page alignment is required for apps targeting Android 15+ on 16 KB devices;
# NDK r27 does not do it by default.
target_link_options(palisade PRIVATE
    -Wl,-z,relro -Wl,-z,now
    -Wl,-z,max-page-size=16384)
